import { useState, useEffect } from "react"
import { Users, TrendingUp, CheckCircle, Activity, UserCheck } from "lucide-react"
import TotalUsersChart from "./components/total-users-chart"
import RegistrationTrendsChart from "./components/registration-trends-chart"
import VerificationStatusChart from "./components/verification-status-chart"
import ActiveUsersChart from "./components/active-users-chart"
import VerificationRateChart from "./components/verification-rate-chart"
import StatsCard from "./components/stats-card"

interface UserStats {
  total_users: Array<{ user_type: string; total_users: string }>
  registration_trends: Array<{ reg_date: string; user_type: string; reg_count: string }>
  verification_status: Array<{ user_type: string; verification_status: string; user_count: string }>
}

interface UserStats1 {
  active_users: Array<{ user_type: string; is_active: string; user_count: string }>
  verification_completion_rate: Array<{ user_type: string; verification_rate: string }>
}

const StatsPage = () => {
  const [userStats, setUserStats] = useState<UserStats | null>(null)
  const [userStats1, setUserStats1] = useState<UserStats1 | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchAnalytics = async () => {
      try {
        setLoading(true)
        setError(null)

        console.log("Attempting to fetch analytics data...")

        const fetchWithTimeout = async (url: string, timeout = 100000) => {
          const controller = new AbortController()
          const timeoutId = setTimeout(() => controller.abort(), timeout)

          try {
            const response = await fetch(url, {
              signal: controller.signal,
              mode: "cors",
              headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
              },
            })
            clearTimeout(timeoutId)
            return response
          } catch (error) {
            clearTimeout(timeoutId)
            throw error
          }
        }

        console.log("Fetching userstats...")
        const userStatsResponse = await fetchWithTimeout(
          "https://y6hlsfi2w2.execute-api.us-east-2.amazonaws.com/dev/analytics/userstats",
        )

        if (!userStatsResponse.ok) {
          throw new Error(`HTTP error! status: ${userStatsResponse.status}`)
        }

        const userStatsData = await userStatsResponse.json()
        const parsedUserStats = JSON.parse(userStatsData.body)
        setUserStats(parsedUserStats)
        console.log("Successfully fetched userstats:", parsedUserStats)

        console.log("Fetching userstats1...")
        const userStats1Response = await fetchWithTimeout(
          "https://y6hlsfi2w2.execute-api.us-east-2.amazonaws.com/dev/analytics/userstats1",
        )

        if (!userStats1Response.ok) {
          throw new Error(`HTTP error! status: ${userStats1Response.status}`)
        }

        const userStats1Data = await userStats1Response.json()
        const parsedUserStats1 = JSON.parse(userStats1Data.body)
        setUserStats1(parsedUserStats1)
        console.log("Successfully fetched userstats1:", parsedUserStats1)
      } catch (err) {
        console.error("Error in fetchAnalytics:", err)
        setError("Failed to fetch analytics data. Please check your network connection and try again.")
      } finally {
        setLoading(false)
      }
    }

    fetchAnalytics()
  }, [])

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading analytics data...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 flex items-center justify-center">
        <div className="text-center">
          <div className="text-red-500 text-xl mb-4">⚠️</div>
          <p className="text-red-600 mb-4">{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-lg transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  const totalUsers = userStats?.total_users.reduce((sum, user) => sum + Number.parseInt(user.total_users), 0) || 0
  const totalActiveUsers =
    userStats1?.active_users.reduce((sum, user) => sum + Number.parseInt(user.user_count), 0) || 0
  const averageVerificationRate =
    userStats1?.verification_completion_rate.reduce((sum, rate) => sum + Number.parseFloat(rate.verification_rate), 0) /
      (userStats1?.verification_completion_rate.length || 1) || 0

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
      <div className="bg-white/95 backdrop-blur-sm border-b border-gray-200 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">Analytics Dashboard</h1>
              <p className="text-gray-600 mt-1">Comprehensive insights into user activity</p>
            </div>
            <div className="flex items-center space-x-2">
              <div className="text-2xl">🛴</div>
              <span className="text-xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                DALScooter
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
          <StatsCard
            title="Total Users"
            value={totalUsers.toString()}
            icon={<Users className="w-6 h-6" />}
            color="blue"
            tooltip="Total count of all users in the system. Helps understand user base size and distribution."
          />
          <StatsCard
            title="Active Users"
            value={totalActiveUsers.toString()}
            icon={<Activity className="w-6 h-6" />}
            color="green"
            tooltip="Number of users who are currently active in the system. Tracks user engagement and platform usage."
          />
          <StatsCard
            title="Avg Verification Rate"
            value={`${averageVerificationRate.toFixed(1)}%`}
            icon={<CheckCircle className="w-6 h-6" />}
            color="purple"
            tooltip="Average verification completion rate across all user types. Shows the percentage of users who have completed the verification process."
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          <div className="relative bg-white rounded-2xl p-6 shadow-lg border border-gray-200 hover:shadow-xl transition-all duration-300 group">
            <div className="flex items-center mb-4">
              <Users className="w-5 h-5 text-blue-600 mr-2" />
              <h2 className="text-xl font-semibold text-gray-900">User Distribution</h2>
            </div>
            {userStats && <TotalUsersChart data={userStats.total_users} />}

            <div className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
              <div className="bg-gray-900 text-white text-xs rounded-lg py-2 px-3 max-w-xs">
                Shows the distribution of users by type. Helps understand user base composition and growth trends over
                time.
              </div>
            </div>
          </div>

          <div className="relative bg-white rounded-2xl p-6 shadow-lg border border-gray-200 hover:shadow-xl transition-all duration-300 group">
            <div className="flex items-center mb-4">
              <UserCheck className="w-5 h-5 text-green-600 mr-2" />
              <h2 className="text-xl font-semibold text-gray-900">Verification Status</h2>
            </div>
            {userStats && <VerificationStatusChart data={userStats.verification_status} />}

            <div className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
              <div className="bg-gray-900 text-white text-xs rounded-lg py-2 px-3 max-w-xs">
                Shows the verification status distribution of users (verified vs pending). Helps track verification
                completion rates.
              </div>
            </div>
          </div>
        </div>

        <div className="relative bg-white rounded-2xl p-6 shadow-lg border border-gray-200 mb-8 hover:shadow-xl transition-all duration-300 group">
          <div className="flex items-center mb-4">
            <TrendingUp className="w-5 h-5 text-purple-600 mr-2" />
            <h2 className="text-xl font-semibold text-gray-900">Registration Trends</h2>
          </div>
          {userStats && <RegistrationTrendsChart data={userStats.registration_trends} />}

          <div className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
            <div className="bg-gray-900 text-white text-xs rounded-lg py-2 px-3 max-w-xs">
              Shows daily registration patterns over time, grouped by user type. Tracks growth trends and identifies
              peak registration periods for business insights.
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="relative bg-white rounded-2xl p-6 shadow-lg border border-gray-200 hover:shadow-xl transition-all duration-300 group">
            <div className="flex items-center mb-4">
              <Activity className="w-5 h-5 text-blue-600 mr-2" />
              <h2 className="text-xl font-semibold text-gray-900">Active Users</h2>
            </div>
            {userStats1 && <ActiveUsersChart data={userStats1.active_users} />}

            <div className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
              <div className="bg-gray-900 text-white text-xs rounded-lg py-2 px-3 max-w-xs">
                Shows the count of active users by user type. Helps understand current user engagement levels.
              </div>
            </div>
          </div>

          <div className="relative bg-white rounded-2xl p-6 shadow-lg border border-gray-200 hover:shadow-xl transition-all duration-300 group">
            <div className="flex items-center mb-4">
              <CheckCircle className="w-5 h-5 text-purple-600 mr-2" />
              <h2 className="text-xl font-semibold text-gray-900">Verification Completion Rate</h2>
            </div>
            {userStats1 && <VerificationRateChart data={userStats1.verification_completion_rate} />}

            <div className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
              <div className="bg-gray-900 text-white text-xs rounded-lg py-2 px-3 max-w-xs">
                Shows the percentage of users who have completed verification by user type. Tracks verification success
                rates.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default StatsPage
