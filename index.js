// index.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Root endpoint
app.get('/', (req, res) => {
  res.send(`
    <h2>🧠 Real-Time Free ChatGPT API</h2>
    <p>Send POST request to <code>/chat</code> with JSON body like: <code>{ "message": "Your question" }</code></p>
  `);
});

// Real-time ChatGPT API endpoint
app.post('/chat', async (req, res) => {
  const { message } = req.body;

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'Invalid message format. Use { "message": "your message" }' });
  }

  try {
    const response = await axios.post('https://gpt.navsharma.com/api/chat', {
      message
    });

    const reply = response.data.message;
    res.json({ reply });
  } catch (error) {
    console.error('GPT Error:', error.message);
    res.status(500).json({ error: 'Failed to get response from GPT service.' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
