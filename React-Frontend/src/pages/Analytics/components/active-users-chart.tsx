import type React from "react"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"

interface ActiveUsersData {
  user_type: string
  is_active: string
  user_count: string
}

interface ActiveUsersChartProps {
  data: ActiveUsersData[]
}

const ActiveUsersChart: React.FC<ActiveUsersChartProps> = ({ data }) => {
  const chartData = data.map((item) => ({
    userType: item.user_type,
    activeUsers: Number.parseInt(item.user_count),
    isActive: item.is_active === "true",
  }))

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload
      return (
        <div className="bg-white p-3 border border-gray-200 rounded-lg shadow-lg">
          <p className="font-semibold text-gray-900">{label}</p>
          <p className="text-sm text-gray-600">
            Active Users: <span className="font-medium">{payload[0].value}</span>
          </p>
          <p className="text-sm text-gray-600">
            Status: <span className="font-medium">{data.isActive ? "Active" : "Inactive"}</span>
          </p>
        </div>
      )
    }
    return null
  }

  return (
    <div className="h-80">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
          <XAxis dataKey="userType" stroke="#6b7280" fontSize={12} />
          <YAxis stroke="#6b7280" fontSize={12} />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="activeUsers" radius={[8, 8, 0, 0]} fill="#10B981" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

export default ActiveUsersChart
