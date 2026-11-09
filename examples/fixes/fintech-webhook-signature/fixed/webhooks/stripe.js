router.post('/webhooks/stripe', express.raw({ type: '*/*' }), (req, res) => {
  const event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.WEBHOOK_SECRET);
  if (event.type === 'payment_intent.succeeded') markPaid(event.data.object.id);
  res.sendStatus(200);
});
