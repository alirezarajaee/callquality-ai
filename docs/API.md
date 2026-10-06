# CallQuality AI — Local HTTP API

The local HTTP API exposes the CallQuality AI analysis engine to the future web dashboard.

## Start the server

From the `app` directory:

```bat
go run ./cmd/callquality-api
```

Default address:

```text
http://127.0.0.1:8080
```

Optional configuration:

```bat
go run ./cmd/callquality-api -listen 127.0.0.1:8080 -max-upload-mb 64
```

## Health

```http
GET /api/v1/health
```

Example response:

```json
{
  "status": "ok"
}
```

## Version

```http
GET /api/v1/version
```

Example response:

```json
{
  "name": "CallQuality AI",
  "version": "0.1.0",
  "api_version": "1",
  "ml_model": "Random Forest v1"
}
```

## Analyze a PCAP

```http
POST /api/v1/analyze
Content-Type: multipart/form-data
```

The multipart field must be named `file`.

PowerShell example:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8080/api/v1/analyze" `
  -Method Post `
  -Form @{ file = Get-Item "..\samples\synthetic-call.pcap" }
```

The response contains:

```text
capture
└── packet / SIP / RTCP summary

calls[]
├── call-level quality
├── E-model / MOS
├── primary diagnosis
└── streams[]
    ├── RTP metrics
    ├── RTCP metrics
    ├── engineering quality factors
    ├── E-model
    ├── diagnosis findings
    └── native ML prediction
```

The API only returns the original upload filename in the response. Temporary server-side upload
paths are not exposed.

## Limits

The default maximum upload size is 64 MiB.

The current capture reader supports classic `.pcap` uploads.
