Fixed

- **I2P comes back after i2pd restarts.** When i2pd restarted, the node rebuilt its SAM session only when an I2P dial failed, so a node that mostly waits for incoming peers stayed unreachable on I2P and kept announcing its address. The Electrum and Esplora I2P sessions were never rebuilt. The node now notices a closed SAM session, stops announcing the I2P address, and rebuilds every session with its saved destination and forward, retrying with Core's I2P backoff.
