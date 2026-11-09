router.post('/webhooks/stripe', (req, res) => {
  const event = req.body;
  if (event.type === 'payment_intent.succeeded') markPaid(event.data.object.id);
  res.sendStatus(200);
});
