// index.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Root
app.get('/', (req, res) => {
  res.send(`
    <h2>🧠 Juned's Advanced GPT API</h2>
    <ul>
      <li>POST <code>/chat</code> – Deep research ChatGPT</li>
      <li>POST <code>/image</code> – Dolphin image generator</li>
      <li>GET <code>/system</code> – Developer info</li>
      <li>GET <a href="/docs" target="_blank">/docs</a> – API documentation</li>
    </ul>
  `);
});

// ChatGPT Deep Research API
app.post('/chat', async (req, res) => {
  const { message } = req.body;
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'Invalid message format. Use { "message": "your message" }' });
  }

  try {
    const response = await axios.post('https://gpt.navsharma.com/api/chat', {
      message: `Answer with deep research and maximum accuracy:\n\n${message}`
    });
    res.json({ reply: response.data.message });
  } catch (error) {
    console.error('GPT Error:', error.message);
    res.status(500).json({ error: 'Failed to get response from GPT.' });
  }
});

// Dolphin Image Generator
app.post('/image', async (req, res) => {
  const { prompt } = req.body;
  if (!prompt || typeof prompt !== 'string') {
    return res.status(400).json({ error: 'Invalid prompt. Use { "prompt": "your image idea" }' });
  }

  const imageUrl = `https://source.unsplash.com/featured/?${encodeURIComponent(prompt + ', dolphin')}`;
  res.json({ prompt, image: imageUrl });
});

// System Info
app.get('/system', (req, res) => {
  res.json({
    developer: "Shaikh Juned",
    role: "Blind Tools Developer",
    location: "Gujarat, India",
    focus: "Accessible AI, ChatGPT Tools, Image AI, Firebase",
    github: "https://github.com/Blindtools"
  });
});

// Documentation
app.get('/docs', (req, res) => {
  res.sendFile(__dirname + '/docs.html');
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Juned's GPT API running on http://localhost:${PORT}`);
});

