using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Haruka.Arcade.SegAPI {
    
    /// <summary>
    /// Class for interacting with SegAPI.
    /// https://github.com/akechi-haruka/segapi
    /// </summary>
    public class SegatoolsAPI3 {

        /// <summary>
        /// Valid packet ID values.
        /// </summary>
        public enum Packet : byte {
            Ping = 20,
            Ack = 21,
            Test = 22,
            Service = 23,
            Credit = 24,
            CardReadFelica = 25,
            CardReadAime = 26,
            PlaySequence = 28,
            VFDTextUTF = 29,
            VFDTextShiftJIS = 30,
            SetCardReaderState = 31,
            SetCardReaderBlocked = 32,
            SetCardReaderRGB = 33,
            ExitGame = 34,
        }

        /// <summary>
        /// The currently configured group ID.
        /// </summary>
        public byte GroupId { get; }
        
        /// <summary>
        /// The currently configured device ID.
        /// </summary>
        public byte DeviceId { get; }
        
        /// <summary>
        /// The currently configured UDP broadcast address.
        /// </summary>
        public IPAddress BroadcastAddress { get; }
        
        /// <summary>
        /// The currently configured UDP port.
        /// </summary>
        public int Port { get; }
        
        /// <summary>
        /// True if the API listener is running.
        /// </summary>
        public bool Running { get; private set; }
        
        private bool connected;
        
        /// <summary>
        /// True if anything was received on the API listener.
        /// </summary>
        public bool Connected {
            get => connected;
            set {
                connected = value;
                OnConnectedChange?.Invoke(value);
            }
        }
        private readonly UdpClient udp;
        private Thread thread;

        /// <summary>
        /// Fired when a TEST packet is received.
        /// </summary>
        public event Action OnTest;
        /// <summary>
        /// Fired when a SERVICE packet is received.
        /// </summary>
        public event Action OnService;
        /// <summary>
        /// Fired when a CREDIT packet is received.
        /// </summary>
        public event Action<int> OnCredit;
        /// <summary>
        /// Fired when a EXIT_GAME packet is received.
        /// </summary>
        public event Action OnExitGame;
        /// <summary>
        /// Fired when the connection status changes.
        /// </summary>
        public event Action<bool> OnConnectedChange;
        /// <summary>
        /// Fired when a FeliCa card is received.
        /// </summary>
        public event Action<byte[]> OnFelica;
        /// <summary>
        /// Fired when a Aime card is received.
        /// </summary>
        public event Action<byte[]> OnAime;
        /// <summary>
        /// Fired when a BLOCK_CARD_READER packet is received.
        /// </summary>
        public event Action<bool> OnCardReaderBlocking;
        /// <summary>
        /// Fired when a message should be written to log.
        /// </summary>
        public static event Action<string> OnLogMessage;

        /// <summary>
        /// Creates a new SegAPI listener.
        /// </summary>
        /// <param name="groupid">The group ID. Groups do not see each other.</param>
        /// <param name="deviceid">The device ID. All devices in the same group see each other.</param>
        /// <param name="broadcast">The UDP broadcast address.</param>
        /// <param name="port">The UDP port.</param>
        public SegatoolsAPI3(byte groupid, byte deviceid, String broadcast = "255.255.255.255", int port = 5364) {
            OnLogMessage?.Invoke("Created group " + groupid + ", device " + deviceid + " with " + broadcast + ":" + port);
            GroupId = groupid;
            DeviceId = deviceid;
            BroadcastAddress = IPAddress.Parse(broadcast);
            Port = port;
            udp = new UdpClient() {
                EnableBroadcast = true,
                ExclusiveAddressUse = false
            };
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udp.Client.Bind(new IPEndPoint(IPAddress.Any, Port));
        }

        /// <summary>
        /// Starts the SegAPI listener. No-op if already started.
        /// </summary>
        public void Start() {
            if (Running) { return; }
            OnLogMessage?.Invoke("Starting device ID " + GroupId);
            Running = true;
            thread = new Thread(StartT) {
                Name = "Segatools API"
            };
            thread.Start();
        }

        private void StartT() {
            while (Running) {
                try {
                    IPEndPoint pt = new IPEndPoint(IPAddress.Any, Port);
                    byte[] data = udp.Receive(ref pt);
                    if (data != null) {
                        OnLogMessage?.Invoke("Received " + data.Length + " bytes from " + pt);
                        byte id = data[0];
                        byte grpid = data[1];
                        byte devid = data[2];
                        byte len = data[3];
                        if (grpid != GroupId) {
                            OnLogMessage?.Invoke("Not our group ID: " + grpid);
                            continue;
                        }
                        if (devid == DeviceId) {
                            OnLogMessage?.Invoke("Our own device ID, skipping");
                            continue;
                        }
                        byte[] inner = new byte[len];
                        Array.Copy(data, 4, inner, 0, len);
                        Handle((Packet)id, inner, pt);
                    }
                } catch (Exception ex) {
                    if (Running) {
                        OnLogMessage?.Invoke("Error while listening on " + BroadcastAddress + ":" + Port + " - " + ex);
                    }
                }
            }
            OnLogMessage?.Invoke("Stopped device ID " + GroupId);
            Connected = false;
            Running = false;
        }

        /// <summary>
        /// Stops the SegAPI listener. No-op if already stopped.
        /// </summary>
        public void Stop() {
            Running = false;
            try {
                udp?.Close();
            } catch { }
        }

        private void Handle(Packet id, byte[] inner, IPEndPoint pt) {
            OnLogMessage?.Invoke("Received packet id " + id);
            if (!Connected) {
                Connected = true;
            }
            if (id == Packet.Ping) {
                Send(pt, Packet.Ack, new byte[] { (byte)id });
            } else if (id == Packet.Ack) {
            } else if (id == Packet.Test) {
                OnTest?.Invoke();
                Send(pt, Packet.Ack, new byte[] { (byte)id });
            } else if (id == Packet.Service) {
                OnService?.Invoke();
                Send(pt, Packet.Ack, new byte[] { (byte)id });
            } else if (id == Packet.Credit) {
                int credit = 1;
                if (inner.Length > 0) {
                    credit = inner[0];
                }
                OnCredit?.Invoke(credit);
                Send(pt, Packet.Ack, new byte[] { (byte)id });
            } else if (id == Packet.CardReadFelica) {
                OnFelica?.Invoke(inner);
                Send(pt, Packet.Ack, new byte[] { (byte)id });
            } else if (id == Packet.CardReadAime) {
                OnAime?.Invoke(inner);
                Send(pt, Packet.Ack, new byte[] { (byte)id });
            } else if (id == Packet.SetCardReaderBlocked) {
                OnCardReaderBlocking?.Invoke(inner[0] != 0);
                Send(pt, Packet.Ack, new byte[] { (byte)id });
            } else if (id == Packet.ExitGame) {
                OnExitGame?.Invoke();
                Send(pt, Packet.Ack, new byte[] { (byte)id });
            }
        }

        private void Send(IPEndPoint pt, Packet id, byte[] data) {
            byte[] outdata = new byte[data.Length + 4];
            outdata[0] = (byte)id;
            outdata[1] = GroupId;
            outdata[2] = DeviceId;
            outdata[3] = (byte)data.Length;
            Array.Copy(data, 0, outdata, 4, data.Length);
            OnLogMessage?.Invoke("Sending packet " + id + " to " + pt);
            udp.Send(outdata, outdata.Length, pt);
        }

        public void SetVFDMessage(String str) {
            OnLogMessage?.Invoke("VFD: " + str);
            Send(new IPEndPoint(BroadcastAddress, Port), Packet.VFDTextUTF, Encoding.UTF8.GetBytes(str));
        }

        public void SendCredit(uint count) {
            Send(new IPEndPoint(BroadcastAddress, Port), Packet.Credit, new byte[] { (byte)(int)count });
        }

        public void SetCardReaderStatus(bool v) {
            Send(new IPEndPoint(BroadcastAddress, Port), Packet.SetCardReaderState, new byte[] { (byte)(v ? 1 : 0) });
        }

        public void SetCardReaderRGB(byte r, byte g, byte b) {
            Send(new IPEndPoint(BroadcastAddress, Port), Packet.SetCardReaderRGB, new byte[] { r, g, b });
        }

        public void SendPing() {
            Send(new IPEndPoint(BroadcastAddress, Port), Packet.Ping, new byte[0]);
        }

        public void SendExitGame() {
            Send(new IPEndPoint(BroadcastAddress, Port), Packet.ExitGame, new byte[0]);
        }
    }
}
