"use client"

import { useEffect, useRef, useState } from "react"
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
} from "recharts"
import { cn } from "@/lib/utils"

interface QueryTypeData {
  name: string
  value: number
  color?: string
  [key: string]: string | number | undefined
}

interface QueryTypesChartProps {
  data: QueryTypeData[]
  className?: string
  title?: string
}

const COLORS = [
  "#10b981", // emerald (SELECT)
  "#f59e0b", // amber (UPDATE)
  "#6366f1", // indigo (INSERT)
  "#ef4444", // red (DELETE)
  "#8b5cf6", // violet (OTHER)
]

export function QueryTypesChart({
  data,
  className,
  title = "Query Types Distribution",
}: QueryTypesChartProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [size, setSize] = useState({ width: 0, height: 0 })
  const total = data.reduce((sum, item) => sum + item.value, 0)

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
          <PieChart width={size.width} height={size.height}>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={90}
              paddingAngle={2}
              dataKey="value"
              label={({ name, percent }) =>
                `${String(name ?? '')} ${((percent ?? 0) * 100).toFixed(0)}%`
              }
              labelLine={false}
              isAnimationActive={false}
            >
              {data.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={entry.color || COLORS[index % COLORS.length]}
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "#1f2937",
                border: "1px solid #374151",
                borderRadius: "8px",
                color: "#f9fafb",
              }}
              formatter={(value: number) => [
                `${value} (${((value / total) * 100).toFixed(1)}%)`,
                "Count",
              ]}
            />
            <Legend
              wrapperStyle={{
                color: "#9ca3af",
                fontSize: "12px",
              }}
            />
          </PieChart>
        ) : (
          <div className="w-full h-full bg-gray-800/50 rounded animate-pulse" />
        )}
      </div>
    </div>
  )
}
