"use client"

import { useEffect, useRef, useState } from "react"
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts"
import { cn } from "@/lib/utils"

interface DataPoint {
  timestamp: string
  value: number
  queries?: number
  masked?: number
}

interface ConnectionsChartProps {
  data: DataPoint[]
  className?: string
  title?: string
  color?: string
  gradientId?: string
}

export function ConnectionsChart({
  data,
  className,
  title = "Connections Over Time",
  color = "#6366f1",
  gradientId = "connectionsGradient",
}: ConnectionsChartProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [size, setSize] = useState({ width: 0, height: 0 })

  useEffect(() => {
    const updateSize = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect()
        setSize({ width: Math.floor(rect.width), height: Math.floor(rect.height) })
      }
    }

    // Initial size after mount
    updateSize()

    // Observe resize
    const observer = new ResizeObserver(updateSize)
    if (containerRef.current) {
      observer.observe(containerRef.current)
    }

    return () => observer.disconnect()
  }, [])

  return (
    <div className={cn("w-full h-[300px]", className)}>
      {title && (
        <h4 className="text-sm font-medium text-gray-400 mb-4">{title}</h4>
      )}
      <div ref={containerRef} className="w-full h-[calc(100%-2rem)]">
        {size.width > 0 && size.height > 0 ? (
          <AreaChart
            width={size.width}
            height={size.height}
            data={data}
            margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
          >
            <defs>
              <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                <stop offset="95%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis
              dataKey="timestamp"
              stroke="#6b7280"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              stroke="#6b7280"
              fontSize={12}
              tickLine={false}
              axisLine={false}
              tickFormatter={(value) => `${value}`}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#1f2937",
                border: "1px solid #374151",
                borderRadius: "8px",
                color: "#f9fafb",
              }}
              labelStyle={{ color: "#9ca3af" }}
            />
            <Area
              type="monotone"
              dataKey="value"
              stroke={color}
              strokeWidth={2}
              fillOpacity={1}
              fill={`url(#${gradientId})`}
              isAnimationActive={false}
            />
          </AreaChart>
        ) : (
          <div className="w-full h-full bg-gray-800/50 rounded animate-pulse" />
        )}
      </div>
    </div>
  )
}

interface MultiLineChartProps {
  data: DataPoint[]
  className?: string
  title?: string
  lines: {
    key: string
    color: string
    name: string
  }[]
}

export function MultiLineChart({
  data,
  className,
  title,
  lines,
}: MultiLineChartProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [size, setSize] = useState({ width: 0, height: 0 })

  useEffect(() => {
    const updateSize = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect()
        setSize({ width: Math.floor(rect.width), height: Math.floor(rect.height) })
      }
    }

    updateSize()

    const observer = new ResizeObserver(updateSize)
    if (containerRef.current) {
      observer.observe(containerRef.current)
    }

    return () => observer.disconnect()
  }, [])

  return (
    <div className={cn("w-full h-[300px]", className)}>
      {title && (
        <h4 className="text-sm font-medium text-gray-400 mb-4">{title}</h4>
      )}
      <div ref={containerRef} className="w-full h-[calc(100%-2rem)]">
        {size.width > 0 && size.height > 0 ? (
          <AreaChart
            width={size.width}
            height={size.height}
            data={data}
            margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
          >
            <defs>
              {lines.map((line) => (
                <linearGradient
                  key={`gradient-${line.key}`}
                  id={`gradient-${line.key}`}
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop offset="5%" stopColor={line.color} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={line.color} stopOpacity={0} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis
              dataKey="timestamp"
              stroke="#6b7280"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              stroke="#6b7280"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#1f2937",
                border: "1px solid #374151",
                borderRadius: "8px",
                color: "#f9fafb",
              }}
              labelStyle={{ color: "#9ca3af" }}
            />
            <Legend
              wrapperStyle={{
                color: "#9ca3af",
                fontSize: "12px",
              }}
            />
            {lines.map((line) => (
              <Area
                key={line.key}
                type="monotone"
                dataKey={line.key}
                name={line.name}
                stroke={line.color}
                strokeWidth={2}
                fillOpacity={1}
                fill={`url(#gradient-${line.key})`}
                isAnimationActive={false}
              />
            ))}
          </AreaChart>
        ) : (
          <div className="w-full h-full bg-gray-800/50 rounded animate-pulse" />
        )}
      </div>
    </div>
  )
}
