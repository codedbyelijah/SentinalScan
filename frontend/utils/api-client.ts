const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// Types matching backend API models
export type ScanMode = 'full' | 'custom';
export type ScheduleInterval = 'hourly' | 'daily' | 'weekly' | 'custom';

export interface StartScanRequest {
  target: string;
  scan_mode: ScanMode;
  enabled_modules?: string[];
}

export interface StartScanResponse {
  scan_id: string;
  status: string;
  message: string;
}

export interface ScheduleScanRequest {
  target: string;
  scan_mode: ScanMode;
  enabled_modules?: string[];
  schedule_type: 'one_time' | 'recurring';
  run_at?: string;
  interval?: ScheduleInterval;
  interval_value?: number;
}

export interface ScheduleScanResponse {
  job_id: string;
  message: string;
}

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Request failed' }));
      throw new Error(error.message || error.detail || 'Request failed');
    }

    return response.json();
  }

  async startScan(request: StartScanRequest): Promise<StartScanResponse> {
    return this.request<StartScanResponse>('/api/scan/start', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async scheduleScan(request: ScheduleScanRequest): Promise<ScheduleScanResponse> {
    return this.request<ScheduleScanResponse>('/api/scan/schedule', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }
}

export const apiClient = new ApiClient();
