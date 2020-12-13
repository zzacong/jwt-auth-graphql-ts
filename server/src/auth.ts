import { sign } from 'jsonwebtoken'
import { REFRESH_TOKEN_SECRET, ACCESS_TOKEN_SECRET } from './constants'
import { User } from './entity/User'

export const createTokens = (user: User) => {
  const refreshToken = sign(
    { userId: user.id, count: user.count },
    REFRESH_TOKEN_SECRET,
    {
      expiresIn: '1000s',
    }
  )

  const accessToken = sign({ userId: user.id }, ACCESS_TOKEN_SECRET, {
    expiresIn: '10s',
  })

  return { refreshToken, accessToken }
}
