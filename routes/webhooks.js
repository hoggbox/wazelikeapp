const express = require('express');
const router = express.Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/User');

// Stripe webhook endpoint (BEFORE bodyParser middleware!)
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle successful checkout
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.metadata.userId || session.client_reference_id;

    if (!userId) {
      console.error('No userId in webhook session:', session.id);
      return res.status(400).json({ error: 'Missing userId' });
    }

    try {
      // ✅ ATOMIC UPDATE: Set premium IMMEDIATELY
      const user = await User.findByIdAndUpdate(
        userId,
        {
          subscriptionStatus: 'active', // ← CRITICAL
          premiumActivatedAt: new Date(),
          stripeCustomerId: session.customer,
          stripeSubscriptionId: session.subscription,
          trialEndsAt: null // ← Clear trial date
        },
        { new: true }
      );

      if (!user) {
        console.error('User not found for webhook:', userId);
        return res.status(404).json({ error: 'User not found' });
      }

      console.log('✅ Premium activated via webhook:', {
        userId: user._id,
        email: user.email,
        subscriptionId: session.subscription
      });

      // Emit Socket.IO event if connected
      if (req.app.get('io')) {
        req.app.get('io').to(userId).emit('premiumActivated', {
          subscriptionStatus: 'active',
          premiumActivatedAt: user.premiumActivatedAt
        });
      }

      res.json({ received: true });
    } catch (error) {
      console.error('Webhook processing error:', error);
      res.status(500).json({ error: 'Webhook processing failed' });
    }
  } else {
    res.json({ received: true });
  }
});

// Handle subscription cancellation
router.post('/webhook', async (req, res) => {
  // ... (existing webhook code, add this case)
  if (event.type === 'customer.subscription.deleted') {
    const subscription = event.data.object;
    await User.findOneAndUpdate(
      { stripeSubscriptionId: subscription.id },
      { subscriptionStatus: 'cancelled' }
    );
  }
  res.json({ received: true });
});

module.exports = router;