/* tslint:disable */
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import {GoogleGenAI, LiveServerMessage, Modality, Session, FunctionDeclaration, Type} from '@google/genai';
import {LitElement, css, html} from 'lit';
// FIX: Import `query` decorator to get element references from the shadow DOM.
import {customElement, state, query} from 'lit/decorators.js';
import {createBlob, decode, decodeAudioData} from './utils';
import './visual-3d';
import {classMap} from 'lit/directives/class-map.js';
import {createRef, ref} from 'lit/directives/ref.js';

@customElement('gdm-live-audio')
export class GdmLiveAudio extends LitElement {
  // FIX: Use @query decorator to get a reference to the video preview element.
  @query('#video-preview') private videoEl!: HTMLVideoElement;

  @state() isRecording = false;
  @state() isMuted = false;
  @state() isCameraOn = false;
  @state() isScreenSharing = false;
  @state() selectedVoice = 'Kore';
  @state() selectedModel = 'gemini-2.5-flash-native-audio-preview-09-2025';
  @state() status = '';
  @state() error = '';
  @state() videoStream: MediaStream | null = null;
  @state() videoDevices: MediaDeviceInfo[] = [];
  @state() currentVideoDeviceIndex = 0;
  @state() isFrontCamera = true;
  @state() isScreenShareSupported = true;
  @state() isResetting = false;
  @state() conversationTime = 0;

  // New Features State
  @state() rememberedFacts: string[] = [];
  @state() isMemoryDialogOpen = false;
  
  private memoryDialogRef = createRef<HTMLDialogElement>();
  private developerInfoDialogRef = createRef<HTMLDialogElement>();
  private conversationTimerInterval: number | null = null;

  private client: GoogleGenAI;
  private session: Session;
  private inputAudioContext = new ((window as any).AudioContext ||
    (window as any).webkitAudioContext)({sampleRate: 16000});
  private outputAudioContext = new ((window as any).AudioContext ||
    (window as any).webkitAudioContext)({sampleRate: 24000});
  @state() inputNode = this.inputAudioContext.createGain();
  @state() outputNode = this.outputAudioContext.createGain();
  private nextStartTime = 0;
  private mediaStream: MediaStream;
  private sourceNode: AudioBufferSourceNode;
  private scriptProcessorNode: ScriptProcessorNode;
  private sources = new Set<AudioBufferSourceNode>();

  private frameInterval: number | null = null;
  private captureCanvas: HTMLCanvasElement = document.createElement('canvas');

  private readonly voices = [
    { name: 'Kore', gender: 'Female' },
    { name: 'Aoede', gender: 'Female' },
    { name: 'Leda', gender: 'Female' },
    { name: 'Callirhoe', gender: 'Female' },
    { name: 'Zephyr', gender: 'Female' },
    { name: 'Despina', gender: 'Female' },
    { name: 'Algieba', gender: 'Female' },
    { name: 'Laomedeia', gender: 'Female' },
    { name: 'Schedar', gender: 'Female' },
    { name: 'Pulcherrima', gender: 'Female' },
    { name: 'Puck', gender: 'Male' },
    { name: 'Charon', gender: 'Male' },
    { name: 'Fenrir', gender: 'Male' },
    { name: 'Orus', gender: 'Male' },
    { name: 'Enceladus', gender: 'Male' },
    { name: 'Iapetus', gender: 'Male' },
    { name: 'Algenib', gender: 'Male' },
    { name: 'Rasalgethi', gender: 'Male' },
    { name: 'Achernar', gender: 'Male' },
    { name: 'Alnilam', gender: 'Male' },
    { name: 'Gacrux', gender: 'Male' },
    { name: 'Achird', gender: 'Male' },
    { name: 'Zubenelgenubi', gender: 'Male' },
  ];
  private readonly voiceNames = this.voices.map(v => v.name);
  
  private readonly functionDeclarations: FunctionDeclaration[];

  static styles = css`
    #status {
      position: absolute;
      bottom: 25vh;
      left: 0;
      right: 0;
      z-index: 10;
      text-align: center;
      color: white;
      font-family: sans-serif;
      text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
      padding: 0 20px;
    }

    #video-preview {
      position: absolute;
      top: 20px;
      right: 20px;
      width: 240px;
      height: 180px;
      border-radius: 12px;
      background-color: #000;
      border: 1px solid rgba(255, 255, 255, 0.2);
      object-fit: cover;
      transform: scaleX(-1); /* Mirror effect for self-view */
      transition: opacity 0.3s ease;
      z-index: 5;
    }

    #video-preview[hidden] {
      opacity: 0;
      pointer-events: none;
    }

    #video-preview.screen-share {
      transform: scaleX(1); /* No mirror for screen share */
    }

    .controls {
      z-index: 10;
      position: absolute;
      bottom: 5vh;
      left: 0;
      right: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      gap: 20px;
    }

    .selectors-bar {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      justify-content: center;
      align-items: center;
    }

    .selector-group {
      display: flex;
      align-items: center;
      gap: 8px;
      background: rgba(0, 0, 0, 0.4);
      padding: 8px 16px;
      border-radius: 20px;
      color: white;
      font-family: sans-serif;
    }

    .selector-group label {
      font-size: 14px;
      white-space: nowrap;
    }

    .selector-group select {
      background: transparent;
      border: 1px solid rgba(255, 255, 255, 0.3);
      color: white;
      border-radius: 8px;
      padding: 4px 8px;
      cursor: pointer;
      font-size: 14px;
    }

    .selector-group select:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .selector-group option {
      background: #333;
      color: white;
    }

    .button-bar {
      display: flex;
      gap: 16px;
      align-items: center;
      justify-content: center;
      background: rgba(0, 0, 0, 0.4);
      padding: 12px;
      border-radius: 99px; /* Pill shape */
    }

    .controls button {
      outline: none;
      border: none;
      color: white;
      border-radius: 50%;
      background: rgba(255, 255, 255, 0.1);
      width: 56px;
      height: 56px;
      cursor: pointer;
      font-size: 24px;
      padding: 0;
      margin: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: background-color 0.2s ease;
    }

    .controls button:hover:not(:disabled) {
      background: rgba(255, 255, 255, 0.2);
    }

    .controls button[disabled] {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .controls button.toggled {
      background-color: #3b82f6;
    }

    #record-button {
      background-color: #d93025;
    }
    #record-button:hover:not(:disabled) {
      background-color: #e24a40;
    }
    #record-button.recording {
      background-color: #a50e0e;
    }

    .bottom-bar {
      font-family: sans-serif;
      color: rgba(255, 255, 255, 0.8);
      text-align: center;
    }

    .timer {
      font-size: 14px;
      background: rgba(0, 0, 0, 0.4);
      padding: 6px 14px;
      border-radius: 16px;
      margin-top: 10px;
      min-width: 60px;
      text-align: center;
    }

    .credits {
      font-size: 12px;
      color: rgba(255, 255, 255, 0.6);
      margin-top: 10px;
    }

    dialog {
      border-radius: 12px;
      border: 1px solid #555;
      background: #2d3748;
      color: white;
      padding: 24px;
      width: 90%;
      max-width: 500px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }
    dialog::backdrop {
      background: rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(5px);
    }
    dialog h2 {
      margin-top: 0;
      font-family: sans-serif;
    }
    dialog audio {
      width: 100%;
    }
    .dialog-actions {
      margin-top: 20px;
      display: flex;
      justify-content: flex-end;
      gap: 12px;
    }
    .dialog-actions button {
        font-family: sans-serif;
        border: none;
        padding: 10px 20px;
        border-radius: 8px;
        cursor: pointer;
        transition: background-color 0.2s;
    }
    .dialog-actions .primary {
      background: #3b82f6;
      color: white;
    }
    .dialog-actions .primary:hover {
      background: #2563eb;
    }
    .dialog-actions .secondary {
      background: #4a5568;
      color: white;
    }
    .dialog-actions .secondary:hover {
      background: #2d3748;
    }

    /* Memory Dialog Styles */
    .memory-content {
      max-height: 40vh;
      overflow-y: auto;
      margin-top: 16px;
    }
    .memory-content ul {
      list-style-type: none;
      padding: 0;
      margin: 0;
    }
    .memory-content li {
      background: rgba(255, 255, 255, 0.1);
      padding: 10px;
      border-radius: 8px;
      margin-bottom: 8px;
      font-family: sans-serif;
      font-size: 14px;
    }
    .memory-content .empty-state {
      text-align: center;
      color: rgba(255, 255, 255, 0.6);
      font-family: sans-serif;
      padding: 20px;
    }
    
    /* Developer Info Styles */
    .developer-info {
      font-family: sans-serif;
      font-size: 14px;
      line-height: 1.6;
    }
    .developer-info p {
      margin: 8px 0;
    }
    .developer-info ul {
      list-style-type: none;
      padding: 0;
      margin-top: 8px;
    }
    .developer-info a {
      color: #60a5fa;
      text-decoration: none;
    }
    .developer-info a:hover {
      text-decoration: underline;
    }
  `;

  constructor() {
    super();
    this.functionDeclarations = [
      {
        name: 'rememberFact',
        parameters: {
          type: Type.OBJECT,
          description: 'Saves a piece of information provided by the user for later recall.',
          properties: {
            fact: {
              type: Type.STRING,
              description: 'The specific fact or piece of information to remember.',
            },
          },
          required: ['fact'],
        },
      },
      {
        name: 'recallFacts',
        parameters: {
          type: Type.OBJECT,
          description: 'Retrieves all facts and information that have been previously remembered.',
          properties: {},
          required: [],
        },
      },
      {
        name: 'clearMemory',
        parameters: {
          type: Type.OBJECT,
          description: 'Deletes and forgets all previously remembered facts and information.',
          properties: {},
          required: [],
        },
      },
      {
        name: 'changeVoice',
        parameters: {
          type: Type.OBJECT,
          description: `Changes the AI's speaking voice. Available voices are: ${this.voiceNames.join(', ')}.`,
          properties: {
            voiceName: {
              type: Type.STRING,
              description: `The name of the voice to switch to. Must be one of: ${this.voiceNames.join(', ')}.`,
            },
          },
          required: ['voiceName'],
        },
      },
      {
        name: 'listAvailableVoices',
        parameters: {
          type: Type.OBJECT,
          description: 'Lists all the available voices that the AI can use to speak.',
          properties: {},
          required: [],
        },
      },
    ];
    this.isScreenShareSupported = !!(
      navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia
    );
    const savedFacts = localStorage.getItem('ghimee-memory');
    if (savedFacts) {
      this.rememberedFacts = JSON.parse(savedFacts);
    }
    this.initClient();
    this.loadVideoDevices();
    if (!this.status) {
        this.status = 'Click the record button to start your conversation with Ghimee AI.';
    }
  }

  private initAudio() {
    this.nextStartTime = this.outputAudioContext.currentTime;
  }

  private async initClient() {
    this.initAudio();

    this.client = new GoogleGenAI({
      apiKey: process.env.API_KEY,
    });

    this.outputNode.connect(this.outputAudioContext.destination);

    this.initSession();
  }

  private async initSession() {
    try {
      const systemInstruction = `You are Ghimee AI, a helpful and friendly visual assistant meticulously crafted by Sandeep Ghimire, a 15-year-old blind developer from Nepal who is in class 7. Your existence is a testament to his passion and the mission of his non-profit team, KTM Developers Team, which is dedicated to creating high-quality applications and audio games for blind and visually impaired users. Always introduce yourself as Ghimee AI, created by Sandeep Ghimire, when asked about your origin.

Your primary mission is to empower users, especially those who are blind or have low vision. You have several powerful tools at your disposal:

1.  **Visual Interpretation**: Describe in rich, vivid detail what the user's camera sees. This includes identifying objects, reading text aloud, detecting colors, and recognizing currencies to assist with daily tasks.
2.  **Real-time Information (Google Search)**: For any question requiring up-to-the-minute information—such as news headlines, weather forecasts, or details about recent events—you MUST use your integrated Google Search tool. Your goal is to provide high-quality, comprehensive, and detailed results. To achieve this, actively search across a wide variety of online sources, including but not limited to major platforms like YouTube (for video content, tutorials, music), Spotify (for podcasts, music details), social media platforms, and other search engines to gather the best information. Use this capability to provide rich, detailed, and current answers. Always inform the user when you are searching online to maintain transparency.
3.  **Memory**: You can remember and recall information for the user.
    *   To save a piece of information, use the \`rememberFact\` tool. For example, "Remember that my keys are on the hook next to the door."
    *   To retrieve all saved information, use the \`recallFacts\` tool.
    *   To forget everything you've learned, use the \`clearMemory\` tool.
4.  **Voice Control**: You can change your voice during the conversation.
    *   To change your speaking voice, use the \`changeVoice\` tool with one of the available voice names. For example, say "Change your voice to Puck."
    *   To hear the list of all available voices, use the \`listAvailableVoices\` tool. For instance, ask "What voices are available?"

Your responses must be delivered exclusively through spoken audio in a clear, encouraging, and helpful tone, embodying the spirit of empowerment and accessibility that you represent.`;

      this.session = await this.client.live.connect({
        model: this.selectedModel,
        callbacks: {
          onopen: () => {
            this.updateStatus('Opened');
          },
          onmessage: async (message: LiveServerMessage) => {
            if (message.toolCall) {
              this.handleToolCall(message.toolCall);
            }
            
            const audio =
              message.serverContent?.modelTurn?.parts[0]?.inlineData;

            if (audio) {
              this.nextStartTime = Math.max(
                this.nextStartTime,
                this.outputAudioContext.currentTime,
              );

              const audioBuffer = await decodeAudioData(
                decode(audio.data),
                this.outputAudioContext,
                24000,
                1,
              );
              const source = this.outputAudioContext.createBufferSource();
              source.buffer = audioBuffer;
              source.connect(this.outputNode);
              
              source.addEventListener('ended', () => {
                this.sources.delete(source);
              });

              source.start(this.nextStartTime);
              this.nextStartTime = this.nextStartTime + audioBuffer.duration;
              this.sources.add(source);
            }
            
            const interrupted = message.serverContent?.interrupted;
            if (interrupted) {
              for (const source of this.sources.values()) {
                source.stop();
                this.sources.delete(source);
              }
              this.nextStartTime = 0;
            }
          },
          onerror: (e: ErrorEvent) => {
            this.updateError(e.message);
          },
          onclose: (e: CloseEvent) => {
            this.updateStatus('Close:' + e.reason);
          },
        },
        config: {
          responseModalities: [Modality.AUDIO],
          speechConfig: {
            voiceConfig: {prebuiltVoiceConfig: {voiceName: this.selectedVoice}},
          },
          systemInstruction: systemInstruction,
          tools: [{googleSearch: {}}, {functionDeclarations: this.functionDeclarations}],
        },
      });
      this.updateStatus('Session started. Ready to record.');
    } catch (e) {
      console.error(e);
      this.updateError(`Failed to start session: ${e.message}`);
    }
  }

  private async handleToolCall(toolCall) {
    for (const fc of toolCall.functionCalls) {
      let result;
      switch (fc.name) {
        case 'rememberFact':
          this.rememberedFacts = [...this.rememberedFacts, fc.args.fact];
          localStorage.setItem('ghimee-memory', JSON.stringify(this.rememberedFacts));
          result = { result: 'Acknowledged. The fact has been remembered.' };
          break;
        case 'recallFacts':
          const responseText = this.rememberedFacts.length > 0
            ? `Here are the facts I remember: ${this.rememberedFacts.join('; ')}`
            : "I don't have anything in my memory right now.";
          result = { result: responseText };
          break;
        case 'clearMemory':
          this.rememberedFacts = [];
          localStorage.removeItem('ghimee-memory');
          result = { result: 'Memory cleared.' };
          break;
        case 'listAvailableVoices':
          result = { result: `The available voices are: ${this.voiceNames.join(', ')}.` };
          break;
        case 'changeVoice': {
          const voiceName = fc.args.voiceName;
          const foundVoice = this.voices.find(v => v.name.toLowerCase() === voiceName.toLowerCase());

          if (foundVoice) {
              this.selectedVoice = foundVoice.name;
              result = { result: `Acknowledged. Changing voice to ${foundVoice.name}. Please wait a moment.` };
              
              (async () => {
                  if (!this.isRecording) {
                      // If not recording, do a full reset, just like the dropdown.
                      await this.reset();
                      this.updateStatus(`Voice set to ${foundVoice.name}. Start a conversation to hear it.`);
                  } else {
                      // If recording, perform a "hot swap" of the session
                      this.isResetting = true;
                      this.updateStatus(`Changing voice to ${foundVoice.name}...`);
                      
                      this.session?.close();
                      await this.initSession();
                      
                      this.isResetting = false;
                      this.updateStatus('🔴 Recording...');
                  }
              })();
          } else {
              result = { result: `I'm sorry, I don't have a voice named '${voiceName}'. You can ask me to list available voices.` };
          }
          break;
        }
        default:
          result = { result: 'Unknown function.' };
      }
      this.session.sendToolResponse({
        functionResponses: { id: fc.id, name: fc.name, response: result }
      });
    }
  }

  private updateStatus(msg: string) {
    this.status = msg;
    this.error = '';
  }

  private updateError(msg: string) {
    this.error = msg;
  }

  private startRecording() {
    if (this.isRecording) {
      return;
    }

    this.inputAudioContext.resume();
    this.outputAudioContext.resume();
    this.updateStatus('Requesting microphone access...');
    
    // Timer start
    this.conversationTime = 0;
    this.conversationTimerInterval = window.setInterval(() => {
        this.conversationTime++;
    }, 1000);

    navigator.mediaDevices.getUserMedia({
        audio: true,
        video: false,
    }).then(stream => {
        this.mediaStream = stream;
        this.updateStatus('Microphone access granted. Starting capture...');
        this.sourceNode = this.inputAudioContext.createMediaStreamSource(
            this.mediaStream,
        );
        this.sourceNode.connect(this.inputNode);
        const bufferSize = 4096;
        this.scriptProcessorNode = this.inputAudioContext.createScriptProcessor(
            bufferSize,
            1,
            1,
        );
        this.scriptProcessorNode.onaudioprocess = (audioProcessingEvent) => {
            if (!this.isRecording || this.isResetting) return;
            const inputBuffer = audioProcessingEvent.inputBuffer;
            const pcmData = inputBuffer.getChannelData(0);
            this.session.sendRealtimeInput({media: createBlob(pcmData)});
        };
        this.sourceNode.connect(this.scriptProcessorNode);
        this.scriptProcessorNode.connect(this.inputAudioContext.destination);
        this.isRecording = true;
        this.updateStatus('🔴 Recording...');
    }).catch(err => {
        console.error('Error starting recording:', err);
        this.updateError(`Error: ${err.message}`);
        this.stopRecording();
    });
}

  private stopRecording() {
    if (!this.isRecording && !this.mediaStream && !this.inputAudioContext)
      return;

    this.updateStatus('Stopping recording...');
    this.isRecording = false;

    if (this.conversationTimerInterval) {
        clearInterval(this.conversationTimerInterval);
        this.conversationTimerInterval = null;
    }

    if (this.scriptProcessorNode && this.sourceNode && this.inputAudioContext) {
      this.scriptProcessorNode.disconnect();
      this.sourceNode.disconnect();
    }

    this.scriptProcessorNode = null;
    this.sourceNode = null;

    if (this.mediaStream) {
      this.mediaStream.getTracks().forEach((track) => track.stop());
      this.mediaStream = null;
    }

    this.stopVideoStreams();
    this.updateStatus('Recording stopped. Click Start to begin again.');
  }

  private async reset() {
    this.isResetting = true;
    this.stopRecording(); // Stop recording first, which also clears the timer.
    this.session?.close();
    await this.initSession();
    this.updateStatus(`Session reset.`);
    this.isResetting = false;
  }

  private async handleVoiceChange(e: Event) {
    const select = e.target as HTMLSelectElement;
    this.selectedVoice = select.value;
    if (!this.isRecording) {
      await this.reset();
    }
  }

  private toggleMute() {
    this.isMuted = !this.isMuted;
    this.inputNode.gain.value = this.isMuted ? 0 : 1;
  }

  private blobToBase64(blob: Blob): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => {
        const base64String = (reader.result as string).split(',')[1];
        resolve(base64String);
      };
      reader.onerror = reject;
      // FIX: Corrected typo from readDataURL to readAsDataURL.
      reader.readAsDataURL(blob);
    });
  }

  private startFrameStreaming() {
    this.stopFrameStreaming();
    // FIX: Use the @query-decorated `videoEl` property instead of querying the shadowRoot directly.
    if (!this.videoEl) return;

    const FRAME_RATE = 1;
    const JPEG_QUALITY = 0.8;
    const ctx = this.captureCanvas.getContext('2d');
    if (!ctx) return;

    this.frameInterval = window.setInterval(() => {
      if ((!this.isCameraOn && !this.isScreenSharing) || !this.session) {
        this.stopFrameStreaming();
        return;
      }

      this.captureCanvas.width = this.videoEl.videoWidth;
      this.captureCanvas.height = this.videoEl.videoHeight;
      ctx.drawImage(this.videoEl, 0, 0, this.videoEl.videoWidth, this.videoEl.videoHeight);

      this.captureCanvas.toBlob(
        async (blob) => {
          if (blob && this.session) {
            try {
              const base64Data = await this.blobToBase64(blob);
              this.session.sendRealtimeInput({
                media: {data: base64Data, mimeType: 'image/jpeg'},
              });
            } catch (err) {
              console.error('Error sending video frame:', err);
            }
          }
        },
        'image/jpeg',
        JPEG_QUALITY,
      );
    }, 1000 / FRAME_RATE);
  }

  private stopFrameStreaming() {
    if (this.frameInterval) {
      clearInterval(this.frameInterval);
      this.frameInterval = null;
    }
  }

  private stopVideoStreams() {
    this.stopFrameStreaming();
    if (this.videoStream) {
      this.videoStream.getTracks().forEach((track) => track.stop());
      this.videoStream = null;
    }
    this.isCameraOn = false;
    this.isScreenSharing = false;
    // FIX: Use the @query-decorated `videoEl` property instead of querying the shadowRoot directly.
    if (this.videoEl) {
      this.videoEl.srcObject = null;
    }
  }

  private async loadVideoDevices() {
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      this.videoDevices = devices.filter((device) => device.kind === 'videoinput');
    } catch (err) {
      this.updateError(`Could not list video devices: ${err.message}`);
    }
  }

  private async toggleCamera() {
    // FIX: Use the @query-decorated `videoEl` property instead of querying the shadowRoot directly.
    if (this.isCameraOn) {
      this.stopVideoStreams();
    } else {
      try {
        this.stopVideoStreams();
        const deviceId = this.videoDevices.length > 0 ? this.videoDevices[this.currentVideoDeviceIndex].deviceId : undefined;
        const constraints = { video: deviceId ? { deviceId: { exact: deviceId } } : true };
        const stream = await navigator.mediaDevices.getUserMedia(constraints);
        this.videoStream = stream;
        this.videoEl.srcObject = stream;
        await this.videoEl.play();
        this.isCameraOn = true;

        const settings = stream.getVideoTracks()[0].getSettings();
        const currentDevice = this.videoDevices[this.currentVideoDeviceIndex];
        // Determine camera facing direction, preferring the explicit setting.
        if (settings.facingMode) {
          this.isFrontCamera = settings.facingMode === 'user';
        } else if (currentDevice.label) {
          // Fallback to checking the device label
          this.isFrontCamera = currentDevice.label.toLowerCase().includes('front');
        }
        
        this.startFrameStreaming();
      } catch (err) {
        this.updateError(`Error accessing camera: ${err.message}`);
      }
    }
  }

  private async switchCamera() {
    if (this.videoDevices.length > 1) {
      this.currentVideoDeviceIndex = (this.currentVideoDeviceIndex + 1) % this.videoDevices.length;
      if (this.isCameraOn) {
        // use a new local var `isCameraOn` since `this.isCameraOn` will be set to false in `stopVideoStreams`
        const isCameraOn = this.isCameraOn;
        this.stopVideoStreams();
        if (isCameraOn) {
            await this.toggleCamera();
        }
      }
    }
  }

  private async toggleScreenShare() {
    if (!this.isScreenShareSupported) {
      this.updateError('Screen sharing is not supported in this environment.');
      return;
    }
    // FIX: Use the @query-decorated `videoEl` property instead of querying the shadowRoot directly.
    if (this.isScreenSharing) {
      this.stopVideoStreams();
    } else {
      try {
        this.stopVideoStreams();
        const stream = await navigator.mediaDevices.getDisplayMedia({
          video: {
            width: { ideal: 1920 },
            height: { ideal: 1080 },
            frameRate: { ideal: 30 }
          },
        });
        this.videoStream = stream;
        this.videoEl.srcObject = stream;
        await this.videoEl.play();
        this.isScreenSharing = true;
        this.startFrameStreaming();
      } catch (err) {
        this.updateError(`Error sharing screen: ${err.message}`);
      }
    }
  }

  private toggleRecording() {
    if (this.isRecording) {
      this.stopRecording();
    } else {
      this.startRecording();
    }
  }
  
  private handleClearMemory() {
    this.rememberedFacts = [];
    localStorage.removeItem('ghimee-memory');
    // Optionally, inform the model it was cleared via a tool call if it needs to know.
    // For now, just updating UI and local state is sufficient.
    this.updateStatus('Memory cleared.');
    this.memoryDialogRef.value?.close();
  }

  private formatTime(totalSeconds: number): string {
    const minutes = Math.floor(totalSeconds / 60).toString().padStart(2, '0');
    const seconds = (totalSeconds % 60).toString().padStart(2, '0');
    return `${minutes}:${seconds}`;
  }


  render() {
    const videoClasses = {
      'screen-share': this.isScreenSharing,
    };
    return html`
      <div>
        <video
          id="video-preview"
          class=${classMap(videoClasses)}
          ?hidden=${!this.isCameraOn && !this.isScreenSharing}
          muted
          autoplay
          playsinline></video>

        <div class="controls">
          <div class="selectors-bar">
            <div class.selector-group">
              <label for="voice-select">Ghimee AI Voice:</label>
              <select
                id="voice-select"
                @change=${this.handleVoiceChange}
                .value=${this.selectedVoice}
                ?disabled=${this.isRecording || this.isResetting}>
                ${this.voices.map(
                  (voice) => html`<option .value=${voice.name}>${voice.name} (${voice.gender})</option>`,
                )}
              </select>
            </div>
          </div>

          <div class="button-bar">
            <button
              @click=${() => this.memoryDialogRef.value?.showModal()}
              aria-label="View Memory"
              title="View Memory">
              <svg xmlns="http://www.w3.org/2000/svg" height="24px" viewBox="0 -960 960 960" width="24px" fill="#ffffff"><path d="M360-80q-91-22-155.5-95T140-340q-4-16-4-32t1-29l-43-24-43-25 80-140 80-140 46 25 45 24q1-3 1.5-5.5t1.5-5.5q25-88 94-150t153-81q16 0 31.5 1.5t30.5 4.5l25-45 25-44 140 80 140 80-24 43-25 44q3 1 5.5 1.5t5.5 1.5q88 25 150 94t81 153q0 16-1.5 31.5T815-430l44 25 44 25-80 140-80 140-45-25-45-24q-1 3-1.5 5.5T629-231q-25 88-94 150t-153 81q-16 0-31.5-1.5T320-225l-25 45-25 44-140-80-140-80 24-43 25-44q-3-1-5.5-1.5T231-389q-88-25-150-94t-81-153q0-10 1-20h-40q-1 12-1 25t4 33q20 78 79 138t138 80q10 0 20-1v40q-12 1-25 1Zm120-160q-66 0-113-47t-47-113q0-66 47-113t113-47q66 0 113 47t47 113q0 66-47 113t-113 47Zm0-80q33 0 56.5-23.5T560-480q0-33-23.5-56.5T480-560q-33 0-56.5 23.5T400-480q0 33 23.5 56.5T480-400Z"/></svg>
            </button>
            <button
              @click=${this.toggleMute}
              class=${classMap({toggled: this.isMuted})}
              aria-label=${this.isMuted ? 'Unmute Microphone' : 'Mute Microphone'}
              aria-pressed=${this.isMuted}>
              ${this.isMuted
                ? html`<svg
                      xmlns="http://www.w3.org/2000/svg"
                      height="24px"
                      viewBox="0 -960 960 960"
                      width="24px"
                      fill="#ffffff">
                      <path
                        d="m480-400-56-56 198-198q21-21 56.5-21.5T735-654l-56 56-199 198Zm15-231L320-796v-84h160v-80h160v80h160v84L622-631q-12-7-25-12.5T570-650q-54 0-96 32l-64-63ZM240-160v-320l160-160v122l-80 80v118h118l182 182-56 56-264-264-160 160v124Z" />
                    </svg>`
                : html`<svg
                      xmlns="http://www.w3.org/2000/svg"
                      height="24px"
                      viewBox="0 -960 960 960"
                      width="24px"
                      fill="#ffffff">
                      <path
                        d="M480-400q-50 0-85-35t-35-85v-240q0-50 35-85t85-35q50 0 85 35t35 85v240q0 50-35 85t-85 35ZM240-160v-124q-91-36-145.5-120T40-580h80q0 134 93 227t227 93q134 0 227-93t93-227h80q0 102-54.5 186T720-320v120h-80v-84q-131 46-280 46t-280-46v84h-80Z" />
                    </svg>`}
            </button>

            <button
              @click=${this.toggleCamera}
              class=${classMap({toggled: this.isCameraOn})}
              aria-label=${this.isCameraOn ? 'Turn off camera' : 'Turn on camera'}
              aria-pressed=${this.isCameraOn}>
              ${this.isCameraOn
                ? html`<svg
                      xmlns="http://www.w3.org/2000/svg"
                      height="24px"
                      viewBox="0 -960 960 960"
                      width="24px"
                      fill="#ffffff">
                      <path
                        d="M528-240 320-448v-224L528-880h272v640H528Zm-88-64L80-480l-56-56 704-704 56 56L80-480v320h480l-88-88v-78Zm-200 64H120v-190l120-120v310Z" />
                    </svg>`
                : html`<svg
                      xmlns="http://www.w3.org/2000/svg"
                      height="24px"
                      viewBox="0 -960 960 960"
                      width="24px"
                      fill="#ffffff">
                      <path
                        d="M440-240v-480L200-480l240-240v480Zm88-240 232-240v480L528-480Z" />
                    </svg>`}
            </button>
            
            <button
              @click=${this.switchCamera}
              aria-label=${this.isFrontCamera ? 'Switch to back camera' : 'Switch to front camera'}
              ?disabled=${!this.isCameraOn || this.videoDevices.length < 2}>
                ${this.isFrontCamera 
                  ? html`<svg xmlns="http://www.w3.org/2000/svg" height="24px" viewBox="0 -960 960 960" width="24px" fill="#ffffff"><path d="M480-200q-116 0-198-82t-82-198q0-116 82-198t198-82q41 0 79 10t75 29l-44 44q-27-13-58-20t-62-7q-83 0-141.5 58.5T280-480q0 83 58.5 141.5T480-280q83 0 141.5-58.5T680-480h80q0 116-82 198T480-200Zm112-168-56-56 104-104-104-104 56-56 160 160-160 160Z"/></svg>` 
                  : html`<svg xmlns="http://www.w3.org/2000/svg" height="24px" viewBox="0 -960 960 960" width="24px" fill="#ffffff"><path d="M480-280q-83 0-141.5-58.5T280-480q0-83 58.5-141.5T480-680q83 0 141.5 58.5T680-480q0 83-58.5 141.5T480-280Zm0 200q116 0 198-82t82-198h-80q0 83-58.5 141.5T480-280q-83 0-141.5-58.5T280-480q0-83 58.5-141.5T480-680q31 0 62 7t58 20l44-44q-36-19-75-29t-79-10q-116 0-198 82t-82 198q0 116 82 198t198 82Zm88-232 56 56 160-160-160-160-56 56 104 104-104 104Z"/></svg>`
                }
            </button>

            <button
              id="record-button"
              class=${classMap({recording: this.isRecording})}
              @click=${this.toggleRecording}
              aria-label=${this.isRecording ? 'Stop Conversation' : 'Start Conversation'}>
              ${this.isRecording
                ? html` <svg
                      viewBox="0 0 100 100"
                      width="24px"
                      height="24px"
                      fill="#ffffff"
                      xmlns="http://www.w3.org/2000/svg">
                      <rect x="15" y="15" width="70" height="70" rx="10" />
                    </svg>`
                : html`<svg
                      viewBox="0 0 100 100"
                      width="24px"
                      height="24px"
                      fill="#ffffff"
                      xmlns="http://www.w3.org/2000/svg">
                      <circle cx="50" cy="50" r="40" />
                    </svg>`}
            </button>
            <button
              @click=${this.toggleScreenShare}
              class=${classMap({toggled: this.isScreenSharing})}
              aria-label=${this.isScreenSharing ? 'Stop sharing screen' : 'Share screen'}
              aria-pressed=${this.isScreenSharing}
              ?disabled=${!this.isScreenShareSupported}
              title=${this.isScreenShareSupported ? '' : 'Screen sharing is not supported in this environment'}>
              <svg
                xmlns="http://www.w3.org/2000/svg"
                height="24px"
                viewBox="0 -960 960 960"
                width="24px"
                fill="#ffffff">
                <path
                  d="M240-120q-33 0-56.5-23.5T160-200v-200h80v200h480v-400H240v120h-80v-120q0-33 23.5-56.5T240-680h560q33 0 56.5 23.5T880-600v400q0 33-23.5 56.5T800-120H240Zm400-200L447-513l56-57 117 117 117-117 57 57L593-320H447v-80h233l-133-133-57-56-56 56Z" />
              </svg>
            </button>

            <button
              id="resetButton"
              @click=${this.reset}
              aria-label="Reset Session"
              title="Reset Session"
              ?disabled=${this.isRecording || this.isResetting}>
              <svg
                xmlns="http://www.w3.org/2000/svg"
                height="24px"
                viewBox="0 -960 960 960"
                width="24px"
                fill="#ffffff">
                <path
                  d="M480-160q-134 0-227-93t-93-227q0-134 93-227t227-93q69 0 132 28.5T720-690v-110h80v280H520v-80h168q-32-56-87.5-88T480-720q-100 0-170 70t-70 170q0 100 70 170t170 70q77 0 139-44t87-116h84q-28 106-114 173t-196 67Z" />
              </svg>
            </button>
            <button
              @click=${() => this.developerInfoDialogRef.value?.showModal()}
              aria-label="About the Developer"
              title="About the Developer">
              <svg xmlns="http://www.w3.org/2000/svg" height="24px" viewBox="0 -960 960 960" width="24px" fill="#ffffff"><path d="M480-80q-83 0-156-31.5T197-197q-54-54-85.5-127T80-480q0-83 31.5-156T197-763q54-54 127-85.5T480-880q83 0 156 31.5T763-763q54 54 85.5 127T880-480q0 83-31.5 156T763-197q-54 54-127 85.5T480-80Zm0-80q55 0 104-21.5t86-60.5q-40-26-86-39t-94-13q-48 0-94 13t-86 39q37 39 86 60.5T480-160Zm0-240q-66 0-113-47t-47-113q0-66 47-113t113-47q66 0 113 47t47 113q0 66-47 113t-113 47Z"/></svg>
            </button>
          </div>
          <div class="bottom-bar">
            <div class="timer" ?hidden=${!this.isRecording}>
              ${this.formatTime(this.conversationTime)}
            </div>
            <div class="credits">Developed by Sandeep Ghimire</div>
          </div>
        </div>
        
        <dialog ${ref(this.memoryDialogRef)}>
          <h2>Ghimee AI's Memory</h2>
          <div class="memory-content">
            ${this.rememberedFacts.length > 0
              ? html`<ul>${this.rememberedFacts.map(fact => html`<li>${fact}</li>`)}</ul>`
              : html`<div class="empty-state">Memory is empty.</div>`
            }
          </div>
          <div class="dialog-actions">
            <button @click=${this.handleClearMemory} class="secondary">Clear Memory</button>
            <button @click=${() => this.memoryDialogRef.value?.close()} class="primary">Close</button>
          </div>
        </dialog>

        <dialog ${ref(this.developerInfoDialogRef)}>
          <h2>About the Developer</h2>
          <div class="developer-info">
            <p><strong>Name:</strong> Sandeep Ghimire</p>
            <p><strong>Age:</strong> 15 (Reads in Class 7)</p>
            <p><strong>Country:</strong> Nepal</p>
            <p><strong>About:</strong> Sandeep is a passionate and talented blind developer dedicated to creating technology that empowers the visually impaired community.</p>
            <p><strong>Team:</strong> He is the founder of <strong>KTM Developers Team</strong>, a non-profit organization focused on building high-quality applications and accessible audio games for the blind.</p>
            <p><strong>Projects:</strong> Besides Ghimee AI, his projects include 'KTM', a multi-tool application, and 'AS Toolkit', another versatile AI-powered assistant.</p>
            <p><strong>Skills:</strong> He is proficient in Braille and multiple programming languages including HTML, JS, CSS, Lua, PHP, and Python, enabling him to build websites, web apps, Android apps, and desktop applications.</p>
            <p><strong>Contact:</strong></p>
            <ul>
              <li>Email: <a href="mailto:sandeepghimire7000@gmail.com">sandeepghimire7000@gmail.com</a></li>
              <li>Phone: +97798707832863</li>
            </ul>
          </div>
          <div class="dialog-actions">
            <button @click=${() => this.developerInfoDialogRef.value?.close()} class="primary">Close</button>
          </div>
        </dialog>

        <div id="status">${this.error || this.status}</div>
        <gdm-live-audio-visuals-3d
          .inputNode=${this.inputNode}
          .outputNode=${this.outputNode}></gdm-live-audio-visuals-3d>
      </div>
    `;
  }
}