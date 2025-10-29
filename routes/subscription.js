const express = require('express');
const router = express.Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');
const rateLimit = require('express-rate-limit');

// Rate limit for Stripe operations
const stripeLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5,
  message: 'Too many payment requests, try again later'
});

// Check subscription status
router.get('/status', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('subscriptionStatus trialEndsAt premiumActivatedAt')
      .lean(); // Faster, no Mongoose doc overhead

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const now = new Date();
    const isPremium = user.subscriptionStatus === 'active';

    // Calculate trial status
    let isTrialActive = false;
    let trialDaysRemaining = 0;

    if (user.subscriptionStatus === 'trial' && user.trialEndsAt) {
      const trialEndDate = new Date(user.trialEndsAt);
      isTrialActive = trialEndDate > now;

      if (isTrialActive) {
        trialDaysRemaining = Math.max(0, Math.ceil((trialEndDate - now) / (24 * 60 * 60 * 1000)));
      } else {
        // Auto-expire trial if past due
        await User.findByIdAndUpdate(req.user._id, { subscriptionStatus: 'expired' });
        console.log(`Trial expired for user: ${user._id}`);
      }
    }

    console.log('Subscription Status Check:', {
      userId: user._id,
      email: user.email || 'N/A',
      subscriptionStatus: user.subscriptionStatus,
      isPremium,
      isTrialActive,
      trialDaysRemaining,
      trialEndsAt: user.trialEndsAt
    });

    res.json({
      isPremium,
      isTrialActive,
      trialDaysRemaining,
      trialEndsAt: user.trialEndsAt ? new Date(user.trialEndsAt).toISOString() : null,
      subscriptionStatus: user.subscriptionStatus
    });
  } catch (error) {
    console.error('Error checking subscription status:', error);
    res.status(500).json({ error: 'Failed to check subscription status' });
  }
});

// Create Stripe checkout session
router.post('/create-checkout', stripeLimit, authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Create or retrieve Stripe customer
    let customerId = user.stripeCustomerId;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        metadata: { userId: user._id.toString() }
      });
      customerId = customer.id;
      user.stripeCustomerId = customerId;
      await user.save();
    }

    // Create checkout session
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      client_reference_id: user._id.toString(),
      payment_method_types: ['card'],
      line_items: [{
        price: process.env.STRIPE_PRICE_ID,
        quantity: 1
      }],
      mode: 'subscription',
      success_url: `${process.env.CLIENT_URL}/?payment=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL}/?payment=cancelled`,
      metadata: { userId: user._id.toString() }
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('Checkout creation error:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Cancel subscription (set to cancel at period end)
router.post('/cancel', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user.stripeSubscriptionId) {
      return res.status(400).json({ error: 'No active subscription' });
    }

    await stripe.subscriptions.update(user.stripeSubscriptionId, {
      cancel_at_period_end: true
    });

    res.json({ message: 'Subscription will cancel at period end' });
  } catch (error) {
    console.error('Subscription cancellation error:', error);
    res.status(500).json({ error: 'Failed to cancel subscription' });
  }
});

module.exports = router;