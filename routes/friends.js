const express = require('express');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');
const webpush = require('web-push');
const router = express.Router();

// Send friend request
router.post('/request', authMiddleware, async (req, res) => {
  try {
    const { friendId } = req.body;
    const user = await User.findById(req.user.id);
    const friend = await User.findById(friendId);
    if (!friend) return res.status(404).json({ error: 'Friend not found' });
    if (user.friends.includes(friendId)) return res.status(400).json({ error: 'Already friends' });
    if (user.pendingRequests.includes(friendId)) return res.status(400).json({ error: 'Request pending' });

    friend.pendingRequests.push(req.user.id);
    await friend.save();

    if (friend.pushSubscription) {
      const payload = JSON.stringify({ title: 'Friend Request', body: `${user.username} sent you a friend request!` });
      webpush.sendNotification(friend.pushSubscription, payload);
    }

    res.json({ message: 'Request sent' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to send request' });
  }
});

// Accept friend request
router.post('/accept/:id', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const requesterId = req.params.id;
    if (!user.pendingRequests.includes(requesterId)) return res.status(400).json({ error: 'No pending request' });

    user.pendingRequests.pull(requesterId);
    user.friends.push(requesterId);
    await user.save();

    const requester = await User.findById(requesterId);
    requester.friends.push(req.user.id);
    await requester.save();

    if (requester.pushSubscription) {
      const payload = JSON.stringify({ title: 'Friend Request Accepted', body: `${user.username} accepted your friend request!` });
      webpush.sendNotification(requester.pushSubscription, payload);
    }

    res.json({ message: 'Friend added' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to accept request' });
  }
});

// Get friends list
router.get('/list', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('friends', 'username avatar points');
    res.json(user.friends);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch friends' });
  }
});

module.exports = router;