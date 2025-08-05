import type React from "react"
import { useState } from "react"

interface StatsCardProps {
  title: string
  value: string
  icon: React.ReactNode
  color: "blue" | "green" | "purple" | "orange"
  trend?: string
  tooltip?: string
}

const StatsCard: React.FC<StatsCardProps> = ({ title, value, icon, color, trend, tooltip }) => {
  const [showTooltip, setShowTooltip] = useState(false)

  const colorClasses = {
    blue: "bg-blue-100 text-blue-600",
    green: "bg-green-100 text-green-600",
    purple: "bg-purple-100 text-purple-600",
    orange: "bg-orange-100 text-orange-600",
  }

  const gradientClasses = {
    blue: "from-blue-500 to-blue-600",
    green: "from-green-500 to-green-600",
    purple: "from-purple-500 to-purple-600",
    orange: "from-orange-500 to-orange-600",
  }

  return (
    <div
      className="relative bg-white rounded-2xl p-6 shadow-lg border border-gray-200 transition-all duration-300 hover:shadow-xl hover:scale-105 overflow-visible"
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <div className="flex items-center justify-between mb-4">
        <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${colorClasses[color]}`}>{icon}</div>
        <div className={`h-2 w-16 bg-gradient-to-r ${gradientClasses[color]} rounded-full`}></div>
      </div>
      <div className="mb-2">
        <h3 className="text-sm font-medium text-gray-600 mb-1">{title}</h3>
        <p className="text-3xl font-bold text-gray-900">{value}</p>
      </div>
      {trend && <p className="text-sm text-gray-500">{trend}</p>}

      {showTooltip && tooltip && (
        <div className="absolute inset-0 bg-gray-900/95 backdrop-blur-sm rounded-2xl flex items-center justify-center p-4 z-20 transition-all duration-300">
          <div className="text-white text-sm text-center leading-relaxed">{tooltip}</div>
        </div>
      )}
    </div>
  )
}

export default StatsCard
