import type React from "react"
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts"

interface TotalUsersData {
  user_type: string
  total_users: string
}

interface TotalUsersChartProps {
  data: TotalUsersData[]
}

const TotalUsersChart: React.FC<TotalUsersChartProps> = ({ data }) => {
  const chartData = data.map((item) => ({
    name: item.user_type,
    value: Number.parseInt(item.total_users),
    percentage: (
      (Number.parseInt(item.total_users) / data.reduce((sum, d) => sum + Number.parseInt(d.total_users), 0)) *
      100
    ).toFixed(1),
  }))

  const COLORS = {
    Guest: "#3B82F6",
    Customer: "#10B981",
    Franchise: "#8B5CF6",
  }

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload
      return (
        <div className="bg-white p-3 border border-gray-200 rounded-lg shadow-lg">
          <p className="font-semibold text-gray-900">{data.name}</p>
          <p className="text-sm text-gray-600">
            Users: <span className="font-medium">{data.value}</span>
          </p>
          <p className="text-sm text-gray-600">
            Percentage: <span className="font-medium">{data.percentage}%</span>
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
              <Cell key={`cell-${index}`} fill={COLORS[entry.name as keyof typeof COLORS]} />
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

export default TotalUsersChart
