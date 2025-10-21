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
    console.error('Error creating checkout session:', error.code || error.message, { userId: req.userId });
    res.status(500).json({ error: 'Failed to create checkout session', code: error.code });
  }
});

// Verify payment and activate subscription (idempotent: safe to call multiple times)
router.post('/verify-payment', auth, async (req, res) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) {
      return res.status(400).json({ error: 'Session ID required' });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId, { expand: ['subscription'] });

    if (session.payment_status === 'paid' && session.subscription) {
      const user = await User.findById(req.userId);
      if (user.subscriptionStatus !== 'active') { // Idempotent: only update if needed
        user.subscriptionStatus = 'active';
        user.stripeCustomerId = session.customer;
        user.stripeSubscriptionId = session.subscription.id;
        user.premiumActivatedAt = new Date();
        // End trial if active
        if (user.trialEndsAt && new Date() < user.trialEndsAt) {
          user.trialEndsAt = new Date(); // Mark as ended
        }
        await user.save();

        console.log(`Subscription activated for user ${req.userId} via session ${sessionId}`);
      }
      res.json({ success: true, isPremium: true });
    } else {
      res.status(400).json({ error: 'Payment not completed or no subscription' });
    }
  } catch (error) {
    console.error('Error verifying payment:', error.code || error.message, { sessionId: req.body.sessionId, userId: req.userId });
    res.status(500).json({ error: 'Failed to verify payment', code: error.code });
  }
});

// Webhook for Stripe events (expanded with created event)
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
  try {
    switch (event.type) {
      case 'customer.subscription.created':
        const createdSub = event.data.object;
        await User.findOneAndUpdate(
          { stripeSubscriptionId: createdSub.id },
          { 
            subscriptionStatus: 'active',
            stripeCustomerId: createdSub.customer,
            premiumActivatedAt: new Date()
          }
        );
        console.log(`Subscription created via webhook: ${createdSub.id}`);
        break;
      case 'customer.subscription.deleted':
        const deletedSub = event.data.object;
        await User.findOneAndUpdate(
          { stripeSubscriptionId: deletedSub.id },
          { subscriptionStatus: 'cancelled' }
        );
        console.log(`Subscription deleted via webhook: ${deletedSub.id}`);
        break;
      case 'customer.subscription.updated':
        const updatedSub = event.data.object;
        await User.findOneAndUpdate(
          { stripeSubscriptionId: updatedSub.id },
          { subscriptionStatus: updatedSub.status }
        );
        console.log(`Subscription updated via webhook: ${updatedSub.id} to ${updatedSub.status}`);
        break;
      case 'invoice.payment_failed':
        const failedInvoice = event.data.object;
        await User.findOneAndUpdate(
          { stripeCustomerId: failedInvoice.customer },
          { subscriptionStatus: 'past_due' }
        );
        console.log(`Payment failed for invoice: ${failedInvoice.id}`);
        break;
      default:
        console.log(`Unhandled webhook event: ${event.type}`);
    }
    res.json({ received: true });
  } catch (error) {
    console.error('Error handling webhook event:', error, { eventType: event.type });
    res.status(400).send(`Webhook Error: ${error.message}`);
  }
});

// Cancel subscription (idempotent)
router.post('/cancel', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (user.stripeSubscriptionId && user.subscriptionStatus === 'active') {
      await stripe.subscriptions.cancel(user.stripeSubscriptionId);
      user.subscriptionStatus = 'cancelled';
      await user.save();
      console.log(`Subscription cancelled for user ${req.userId}`);
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error cancelling subscription:', error.code || error.message, { userId: req.userId });
    res.status(500).json({ error: 'Failed to cancel subscription', code: error.code });
  }
});

module.exports = router;