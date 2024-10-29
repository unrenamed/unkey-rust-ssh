# Secure Rust 🦀 SSH Server with Unkey API Keys

A Rust-based SSH echo server, powered by the [russh](https://docs.rs/russh/latest/russh/index.html) package, that leverages [Unkey's API](https://www.unkey.com/docs/api-reference/overview) for secure access management. Unkey enables fine-grained control through time- and quota-limited API keys, adding an extra layer of security to SSH connections. Perfect for developers looking to secure SSH services with modern key-based authentication without sacrificing performance or usability.

## Getting started

### Create a Unkey Root Key

1. Navigate to [Unkey Root Keys](https://app.unkey.com/settings/root-key) and click **"Create New Root Key"**.
2. Name your root key.
3. Select the following workspace permissions:
   - `create_key`
   - `read_key`
   - `encrypt_key`
   - `decrypt_key`
4. Click **"Create"** and save your root key securely.

### Create a Unkey API

1. Go to [Unkey APIs](https://app.unkey.com/apis) and click **"Create New API"**.
2. Enter a name for the API.
3. Click **"Create"**.

### Generate your first API Key

1. From the [Unkey APIs](https://app.unkey.com/apis) page, select your newly created API.
2. Click **"Create Key"** in the top right corner.
3. Fill in the form or leave the default values, then click **"Create"** and save the key for accessing the echoserver.

## Setup

1. Clone the repository to your local machine:

   ```bash
   git clone git@github.com:unrenamed/unkey-rust-ssh
   cd unkey-rust-ssh
   ```

2. Create a `.env` file in the root directory and populate it with the following environment variables:

   ```env
   UNKEY_ROOT_KEY=your-unkey-root-key
   UNKEY_API_ID=your-unkey-api-id
   ```

   Ensure you replace `your-unkey-*` with your actual Unkey credentials.

## Running the example

> You can use any SSH client that suits you best. Below you'll see how to connect using the OpenSSH toolkit.

1. Run `cargo run`. The server will listen on port `2222`.

2. In your terminal, connect with:

   ```bash
   ssh <user>@127.0.0.1 -p 2222
   ```

3. When prompted for a password, enter your Unkey API key.

4. If your key is invalid or expired, access will be denied, and you’ll be prompted again.

5. Upon entering a valid key, you'll see:

   ```bash
   <user> connected to the server.
   ```

6. Connect another user in a new terminal to see messages broadcasted between users.
