# Technical Specification: PCAP Validation with User-Friendly Error Messages

## 1. Overview
The goal of this track is to implement a robust pre-analysis validation for uploaded PCAP files. Currently, incompatible files (such as synthetic or educational PCAPs with inconsistent timestamps) cause the analysis worker to fail with a generic error, providing poor user experience. This feature will detect these issues immediately after upload and provide detailed, actionable feedback.

## 2. Validation Criteria
The validation will use a sample of the first 100 packets to detect the following conditions:
- **Insufficient Packets**: Files with fewer than 2 packets cannot be analyzed for latency.
- **Inconsistent Timestamps**: Jumps larger than 1 year between packets indicate synthetic or "ultimate" PCAP files.
- **High Duplication**: Duplicate packet ratio > 50% indicates corruption or synthetic data.
- **Self-Looping Flows**: Significant amount of traffic where source IP/MAC equals destination IP/MAC.
- **Invalid Format**: Basic check to ensure Scapy can actually parse the file.

## 3. Architecture

### 3.1 Backend Service (`app/services/pcap_validator.py`)
A new service responsible for reading the file and running the heuristics. It will throw a `PCAPValidationError` containing structured details about the failure.

### 3.2 API Integration (`app/api/routes/upload.py`)
The upload endpoint will call the validator after saving the file but before queuing it for analysis. If validation fails, the file is deleted, and a `400 Bad Request` is returned with a structured JSON body.

### 3.3 Data Models (`app/models/schemas.py`)
Updates to include:
- `PCAPValidationErrorDetail`: Title, description, issues list, and suggestions.
- `UploadErrorResponse`: Extension of existing error responses to include validation details.

### 3.4 Frontend Component (`app/templates/components/pcap_error_display.html`)
A new Tailwind-styled component to render the structured error data. It will include:
- A clear warning icon and title.
- Bulleted lists of detected issues.
- Actionable suggestions.
- A direct link to download Wireshark.
- A "Retry" button to reset the UI.

## 4. Security Considerations
- **Resource Protection**: Validation only samples 100 packets to prevent DoS attacks via large file parsing during the validation phase.
- **File Cleanup**: Any file failing validation must be immediately deleted from the `uploads/` directory.
- **Generic Fallback**: Unhandled exceptions during validation should still return a safe, generic error to avoid leaking path information.

## 5. User Experience (UX)
- **Immediate Feedback**: Validation happens synchronously during upload, giving instant feedback.
- **Educational Value**: Instead of "It failed", tell the user *why* (e.g., "Synthetic timestamps detected") and *how* to fix it or where to go instead (Wireshark).
- **Dark Mode**: Component must support `dark:` classes for theme consistency.
