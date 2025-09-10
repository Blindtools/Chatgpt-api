require('dotenv').config();
const express = require('express');
const { Llama } = require('llama-node'); // llama-node package

const app = express();
const port = process.env.PORT || 3000;

// Initialize Llama model
const llama = new Llama({
  model: process.env.MODEL_PATH
});

app.use(express.json());

// Health check endpoint
app.get('/', (req, res) => {
  res.send('🦙 LLaMA API is up and running');
});

// API endpoint for query
app.post('/api/ask', async (req, res) => {
  try {
    const { prompt, max_tokens } = req.body;

    if (!prompt) {
      return res.status(400).json({ error: 'Missing "prompt" in request body.' });
    }

    const response = await llama.generate(prompt, {
      max_tokens: max_tokens || 256,
    });

    res.json({
      prompt: prompt,
      response: response
    });

  } catch (error) {
    console.error('Error generating response:', error);
    res.status(500).json({ error: 'Failed to process the request.' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`🦙 LLaMA API running on http://localhost:${port}`);
});
