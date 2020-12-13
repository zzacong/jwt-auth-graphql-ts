import * as argon2 from 'argon2'
import { IResolvers } from 'graphql-tools'
import { createTokens } from './auth'
import { User } from './entity/User'

export const resolvers: IResolvers = {
  Query: {
    me: (_, __, { req }) => {
      if (!req.userId) return null
      return User.findOne(req.userId)
    },
  },
  Mutation: {
    register: async (_, { email, password }) => {
      const hashedPassword = await argon2.hash(password)
      await User.create({
        email,
        password: hashedPassword,
      }).save()
      return true
    },
    login: async (_, { email, password }, { res }) => {
      const user = await User.findOne({ where: { email } })
      if (!user) return null

      if (!(await argon2.verify(user.password, password))) return null

      const { accessToken, refreshToken } = createTokens(user)
      res.cookie('refresh-token', refreshToken, {
        maxAge: 1000 * 60 * 60 * 24 * 7,
      })
      res.cookie('access-token', accessToken, { maxAge: 1000 * 60 * 15 })
      return user
    },
    invalidateToken: async (_, __, { req }) => {
      if (!req.userId) return false
      const user = await User.findOne(req.userId)
      if (!user) return false
      user.count += 1
      await user.save()
      return true
    },
  },
}
