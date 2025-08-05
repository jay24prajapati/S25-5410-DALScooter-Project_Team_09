import type React from "react"
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts"

interface VerificationStatusData {
  user_type: string
  verification_status: string
  user_count: string
}

interface VerificationStatusChartProps {
  data: VerificationStatusData[]
}

const VerificationStatusChart: React.FC<VerificationStatusChartProps> = ({ data }) => {
  const chartData = data.map((item) => ({
    name: `${item.user_type} - ${item.verification_status}`,
    value: Number.parseInt(item.user_count),
    status: item.verification_status,
    userType: item.user_type,
  }))

  const COLORS = {
    "customer-verified": "#10B981", 
    "customer-pending": "#F59E0B", 
    "customer-rejected": "#EF4444", 
    "franchise-verified": "#3B82F6",
    "franchise-pending": "#8B5CF6",
    "franchise-rejected": "#DC2626", 
  }

  const getColorKey = (userType: string, status: string) => {
    return `${userType.toLowerCase()}-${status.toLowerCase()}`
  }

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload
      return (
        <div className="bg-white p-3 border border-gray-200 rounded-lg shadow-lg">
          <p className="font-semibold text-gray-900">{data.userType}</p>
          <p className="text-sm text-gray-600">
            Status: <span className="font-medium capitalize">{data.status}</span>
          </p>
          <p className="text-sm text-gray-600">
            Count: <span className="font-medium">{data.value}</span>
          </p>
        </div>
      )
    }
    return null
  }

  return (
    <div className="h-80">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={chartData} cx="50%" cy="50%" innerRadius={60} outerRadius={120} paddingAngle={5} dataKey="value">
            {chartData.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={COLORS[getColorKey(entry.userType, entry.status) as keyof typeof COLORS] || "#6B7280"}
              />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
          <Legend
            verticalAlign="bottom"
            height={36}
            formatter={(value, entry) => <span style={{ color: entry.color, fontWeight: 500 }}>{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}

export default VerificationStatusChart
