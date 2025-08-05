import type React from "react"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"

interface VerificationRateData {
  user_type: string
  verification_rate: string
}

interface VerificationRateChartProps {
  data: VerificationRateData[]
}

const VerificationRateChart: React.FC<VerificationRateChartProps> = ({ data }) => {
  const chartData = data.map((item) => ({
    userType: item.user_type,
    rate: Number.parseFloat(item.verification_rate),
  }))

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white p-3 border border-gray-200 rounded-lg shadow-lg">
          <p className="font-semibold text-gray-900">{label}</p>
          <p className="text-sm text-gray-600">
            Verification Rate: <span className="font-medium">{payload[0].value.toFixed(1)}%</span>
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
          <YAxis stroke="#6b7280" fontSize={12} domain={[0, 100]} tickFormatter={(value) => `${value}%`} />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="rate" radius={[8, 8, 0, 0]} fill="#8B5CF6" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

export default VerificationRateChart
