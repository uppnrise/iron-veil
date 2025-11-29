# IronVeil

**IronVeil** is a high-performance, Rust-based database proxy designed for real-time PII (Personally Identifiable Information) anonymization. It sits between your application and your database, intercepting queries and masking sensitive data on the fly without requiring changes to your application code.

## Features

*   **Real-time Anonymization**: Masks PII data (emails, credit cards, phone numbers) in `DataRow` packets.
*   **Zero-Copy Parsing**: Built with `tokio` and `bytes` for high throughput and low latency.
*   **Configurable Rules**: Define masking strategies per table and column.
*   **Live Inspector**: View real-time query logs and data transformations via the web dashboard.
*   **Postgres Compatible**: Works seamlessly with PostgreSQL wire protocol (v3.0).

## Tech Stack

*   **Core**: Rust (Tokio, Axum)
*   **Frontend**: Next.js, Tailwind CSS, Shadcn UI
*   **Deployment**: Docker Compose

## Getting Started

1.  **Start the stack**:
    ```bash
    docker compose up -d --build
    ```

2.  **Access the Dashboard**:
    Open [http://localhost:3000](http://localhost:3000) to view the control plane.

3.  **Connect to the Proxy**:
    Connect your database client to port `6543` instead of `5432`.
    ```bash
    psql -h 127.0.0.1 -p 6543 -U postgres
    ```
