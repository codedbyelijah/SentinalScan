"use client";

import { DashboardLayout } from "../components/dashboard/dashboard-layout";
import { ScanConfiguration } from "../components/dashboard/scan-configuration";

export default function Home() {
  const handleScanStarted = (scanId: string) => {
    console.log("Scan started:", scanId);
    // TODO: Navigate to progress view
  };

  const handleScanScheduled = (jobId: string) => {
    console.log("Scan scheduled:", jobId);
    // TODO: Show confirmation or navigate to scheduler view
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <h1 className="text-3xl font-bold text-text-primary">Dashboard</h1>
        <p className="text-text-muted">
          Welcome to SentinelScan. Configure and manage your security scans from
          here.
        </p>
        <ScanConfiguration
          onScanStarted={handleScanStarted}
          onScanScheduled={handleScanScheduled}
        />
      </div>
    </DashboardLayout>
  );
}
