
func Chain(handlers ...HandlerFunc) HandlerFunc {
	if len(handlers) == 0 {

		return func(_ context.Context, _ dns.ResponseWriter, r *dns.Msg) (*dns.Msg, context.Context, error) {

			return nil, context.Background(), nil

		}

	}
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (*dns.Msg, context.Context, error) {

		if len(handlers) == 1 {

			return handlers[0](ctx, w, r)

		}

		for i := range handlers {

			resp, newCtx, err := handlers[i](ctx, w, r)

			if err != nil || resp != nil {

				return resp, newCtx, err

			}

			ctx = newCtx

			r = new(dns.Msg) // Get fresh message for next handler
		}

		return nil, ctx, nil
	}
}