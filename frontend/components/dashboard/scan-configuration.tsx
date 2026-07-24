"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { apiClient, type ScanMode, type ScheduleInterval } from "../../utils/api-client";
import { cn } from "../../app/utils";

const AVAILABLE_MODULES = [
  "PortScanner",
  "HttpProbe",
  "SecurityHeaderScanner",
  "HTTPMethodScanner",
  "SSLScanner",
  "TechnologyDetector",
  "ContentDiscovery",
] as const;

const scanSchema = z.object({
  target: z.string().min(1, "Target is required"),
  scan_mode: z.enum(["full", "custom"]),
  enabled_modules: z.array(z.string()).optional(),
  execution_mode: z.enum(["now", "schedule"]),
  schedule_type: z.enum(["one_time", "recurring"]).optional(),
  run_at: z.string().optional(),
  interval: z.enum(["hourly", "daily", "weekly", "custom"]).optional(),
  interval_value: z.number().optional(),
});

type ScanFormData = z.infer<typeof scanSchema>;

interface ScanConfigurationProps {
  onScanStarted?: (scanId: string) => void;
  onScanScheduled?: (jobId: string) => void;
}

export function ScanConfiguration({
  onScanStarted,
  onScanScheduled,
}: ScanConfigurationProps) {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const {
    register,
    watch,
    handleSubmit,
    formState: { errors },
  } = useForm<ScanFormData>({
    resolver: zodResolver(scanSchema),
    defaultValues: {
      scan_mode: "full",
      execution_mode: "now",
      enabled_modules: [],
    },
  });

  const scanMode = watch("scan_mode");
  const executionMode = watch("execution_mode");
  const scheduleType = watch("schedule_type");
  const interval = watch("interval");

  const onSubmit = async (data: ScanFormData) => {
    setIsLoading(true);
    setError(null);

    try {
      if (executionMode === "now") {
        const response = await apiClient.startScan({
          target: data.target,
          scan_mode: data.scan_mode as ScanMode,
          enabled_modules:
            data.scan_mode === "custom" ? data.enabled_modules : undefined,
        });
        onScanStarted?.(response.scan_id);
      } else {
        const response = await apiClient.scheduleScan({
          target: data.target,
          scan_mode: data.scan_mode as ScanMode,
          enabled_modules:
            data.scan_mode === "custom" ? data.enabled_modules : undefined,
          schedule_type: data.schedule_type as "one_time" | "recurring",
          run_at: data.schedule_type === "one_time" ? data.run_at : undefined,
          interval: data.schedule_type === "recurring" ? (data.interval as ScheduleInterval) : undefined,
          interval_value: data.interval === "custom" ? data.interval_value : undefined,
        });
        onScanScheduled?.(response.job_id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to submit scan");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <div className="bg-bg-surface border border-border-default rounded-xl p-6">
        <h2 className="text-2xl font-semibold text-text-primary mb-6">
          Configure Scan
        </h2>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
          {/* Target Input */}
          <div>
            <label className="block text-sm font-medium text-text-primary mb-2">
              Target
            </label>
            <input
              type="text"
              placeholder="Enter URL, domain, or IP address"
              {...register("target")}
              className={cn(
                "w-full px-4 py-2 bg-bg-base border border-border-default rounded-md",
                "text-text-primary placeholder:text-text-muted",
                "focus:outline-none focus:ring-2 focus:ring-accent-primary focus:border-transparent",
                errors.target && "border-state-error"
              )}
              disabled={isLoading}
            />
            {errors.target && (
              <p className="mt-1 text-sm text-state-error">{errors.target.message}</p>
            )}
          </div>

          {/* Scan Mode Selection */}
          <div>
            <label className="block text-sm font-medium text-text-primary mb-2">
              Scan Mode
            </label>
            <div className="flex gap-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  value="full"
                  {...register("scan_mode")}
                  className="accent-accent-primary"
                  disabled={isLoading}
                />
                <span className="text-text-primary">Full Scan</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  value="custom"
                  {...register("scan_mode")}
                  className="accent-accent-primary"
                  disabled={isLoading}
                />
                <span className="text-text-primary">Custom Scan</span>
              </label>
            </div>
          </div>

          {/* Module Selection (Custom Mode Only) */}
          {scanMode === "custom" && (
            <div>
              <label className="block text-sm font-medium text-text-primary mb-2">
                Select Modules
              </label>
              <div className="space-y-2">
                {AVAILABLE_MODULES.map((module) => (
                  <label key={module} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      value={module}
                      {...register("enabled_modules")}
                      className="accent-accent-primary"
                      disabled={isLoading}
                    />
                    <span className="text-text-primary">{module}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* Execution Mode */}
          <div>
            <label className="block text-sm font-medium text-text-primary mb-2">
              Execution
            </label>
            <div className="flex gap-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  value="now"
                  {...register("execution_mode")}
                  className="accent-accent-primary"
                  disabled={isLoading}
                />
                <span className="text-text-primary">Start Now</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  value="schedule"
                  {...register("execution_mode")}
                  className="accent-accent-primary"
                  disabled={isLoading}
                />
                <span className="text-text-primary">Schedule</span>
              </label>
            </div>
          </div>

          {/* Schedule Configuration */}
          {executionMode === "schedule" && (
            <div className="space-y-4 p-4 bg-bg-base rounded-md border border-border-default">
              <div>
                <label className="block text-sm font-medium text-text-primary mb-2">
                  Schedule Type
                </label>
                <select
                  {...register("schedule_type")}
                  className={cn(
                    "w-full px-4 py-2 bg-bg-surface border border-border-default rounded-md",
                    "text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary",
                    errors.schedule_type && "border-state-error"
                  )}
                  disabled={isLoading}
                >
                  <option value="one_time">One-time</option>
                  <option value="recurring">Recurring</option>
                </select>
                {errors.schedule_type && (
                  <p className="mt-1 text-sm text-state-error">{errors.schedule_type.message}</p>
                )}
              </div>

              {scheduleType === "one_time" && (
                <div>
                  <label className="block text-sm font-medium text-text-primary mb-2">
                    Run At
                  </label>
                  <input
                    type="datetime-local"
                    {...register("run_at")}
                    className={cn(
                      "w-full px-4 py-2 bg-bg-surface border border-border-default rounded-md",
                      "text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary",
                      errors.run_at && "border-state-error"
                    )}
                    disabled={isLoading}
                  />
                  {errors.run_at && (
                    <p className="mt-1 text-sm text-state-error">{errors.run_at.message}</p>
                  )}
                </div>
              )}

              {scheduleType === "recurring" && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-text-primary mb-2">
                      Interval
                    </label>
                    <select
                      {...register("interval")}
                      className={cn(
                        "w-full px-4 py-2 bg-bg-surface border border-border-default rounded-md",
                        "text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary",
                        errors.interval && "border-state-error"
                      )}
                      disabled={isLoading}
                    >
                      <option value="hourly">Hourly</option>
                      <option value="daily">Daily</option>
                      <option value="weekly">Weekly</option>
                      <option value="custom">Custom</option>
                    </select>
                    {errors.interval && (
                      <p className="mt-1 text-sm text-state-error">{errors.interval.message}</p>
                    )}
                  </div>

                  {interval === "custom" && (
                    <div>
                      <label className="block text-sm font-medium text-text-primary mb-2">
                        Interval Value (minutes)
                      </label>
                      <input
                        type="number"
                        min="1"
                        {...register("interval_value", { valueAsNumber: true })}
                        className={cn(
                          "w-full px-4 py-2 bg-bg-surface border border-border-default rounded-md",
                          "text-text-primary focus:outline-none focus:ring-2 focus:ring-accent-primary",
                          errors.interval_value && "border-state-error"
                        )}
                        disabled={isLoading}
                      />
                      {errors.interval_value && (
                        <p className="mt-1 text-sm text-state-error">{errors.interval_value.message}</p>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* Error Display */}
          {error && (
            <div className="p-3 bg-state-error/10 border border-state-error rounded-md">
              <p className="text-sm text-state-error">{error}</p>
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isLoading}
            className={cn(
              "w-full px-4 py-2 bg-accent-primary text-white rounded-md",
              "font-medium hover:bg-accent-primary/90 transition-colors",
              "disabled:opacity-50 disabled:cursor-not-allowed"
            )}
          >
            {isLoading ? "Submitting..." : executionMode === "now" ? "Start Scan" : "Schedule Scan"}
          </button>
        </form>
      </div>
    </div>
  );
}
