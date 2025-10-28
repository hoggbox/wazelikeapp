const express = require('express');
const router = express.Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/User');
const authMiddleware = require('../middleware/auth'); // Standardized to match server.js
const rateLimit = require('express-rate-limit');

// Rate limit for Stripe operations
const stripeLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 requests per minute
  message: 'Too many payment requests, try again later'
});

// Check subscription status
router.get('/status', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const now = new Date();
    const isPremium = user.subscriptionStatus === 'active';
    
    // Calculate trial status
    let isTrialActive = false;
    let trialDaysRemaining = 0;
    
    if (user.subscriptionStatus === 'trial' && user.trialEndsAt) {
      isTrialActive = user.trialEndsAt > now;
      if (isTrialActive) {
        trialDaysRemaining = Math.ceil((user.trialEndsAt - now) / (24 * 60 * 60 * 1000));
      } else {
        // Trial expired - update user
        user.subscriptionStatus = 'expired';
        await user.save();
      }
    }

    console.log('📊 Subscription Status Check:', {
      userId: user._id,
      email: user.email,
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
      trialEndsAt: user.trialEndsAt,
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
      client_reference_id: user._id.toString(), // For webhook identification
      payment_method_types: ['card'],
      line_items: [{
        price: process.env.STRIPE_PRICE_ID, // Set in .env
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