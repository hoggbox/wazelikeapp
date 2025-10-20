const express = require('express');
const router = express.Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/User');
const auth = require('../middleware/auth');

// Check subscription status
router.get('/status', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    const now = new Date();
    const trialEnd = user.trialEndsAt;
    const isTrialActive = trialEnd && now < trialEnd;
    const isPremium = user.subscriptionStatus === 'active';
    
    res.json({
      isPremium,
      isTrialActive,
      trialEndsAt: user.trialEndsAt,
      trialDaysRemaining: isTrialActive ? Math.ceil((trialEnd - now) / (1000 * 60 * 60 * 24)) : 0,
      subscriptionStatus: user.subscriptionStatus,
      lastReminderSent: user.lastReminderSent
    });
  } catch (error) {
    console.error('Error checking subscription:', error);
    res.status(500).json({ error: 'Failed to check subscription status' });
  }
});

// Create Stripe checkout session
router.post('/create-checkout', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    const session = await stripe.checkout.sessions.create({
      customer_email: user.email,
      payment_method_types: ['card'],
      line_items: [
        {
          price: process.env.STRIPE_PRICE_ID, // Your Stripe price ID
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${process.env.CLIENT_URL}?session_id={CHECKOUT_SESSION_ID}&payment=success`,
      cancel_url: `${process.env.CLIENT_URL}?payment=cancelled`,
      metadata: {
        userId: req.userId
      }
    });

    res.json({ sessionId: session.id, url: session.url });
  } catch (error) {
    console.error('Error creating checkout session:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Verify payment and activate subscription
router.post('/verify-payment', auth, async (req, res) => {
  try {
    const { sessionId } = req.body;
    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (session.payment_status === 'paid') {
      const user = await User.findById(req.userId);
      user.subscriptionStatus = 'active';
      user.stripeCustomerId = session.customer;
      user.stripeSubscriptionId = session.subscription;
      user.premiumActivatedAt = new Date();
      await user.save();

      res.json({ success: true, isPremium: true });
    } else {
      res.status(400).json({ error: 'Payment not completed' });
    }
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({ error: 'Failed to verify payment' });
  }
});

// Webhook for Stripe events
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

  // Handle the event
  switch (event.type) {
    case 'customer.subscription.deleted':
      const subscription = event.data.object;
      await User.findOneAndUpdate(
        { stripeSubscriptionId: subscription.id },
        { subscriptionStatus: 'cancelled' }
      );
      break;
    case 'customer.subscription.updated':
      const updatedSub = event.data.object;
      await User.findOneAndUpdate(
        { stripeSubscriptionId: updatedSub.id },
        { subscriptionStatus: updatedSub.status }
      );
      break;
    case 'invoice.payment_failed':
      const failedInvoice = event.data.object;
      await User.findOneAndUpdate(
        { stripeCustomerId: failedInvoice.customer },
        { subscriptionStatus: 'past_due' }
      );
      break;
  }

  res.json({ received: true });
});

// Cancel subscription
router.post('/cancel', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (user.stripeSubscriptionId) {
      await stripe.subscriptions.cancel(user.stripeSubscriptionId);
      user.subscriptionStatus = 'cancelled';
      await user.save();
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error cancelling subscription:', error);
    res.status(500).json({ error: 'Failed to cancel subscription' });
  }
});

module.exports = router;