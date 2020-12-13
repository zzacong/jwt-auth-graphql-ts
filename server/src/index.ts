import 'reflect-metadata'
import { createConnection } from 'typeorm'
import { ApolloServer } from 'apollo-server-express'
import * as express from 'express'
import * as cookieParser from 'cookie-parser'

import { typeDefs } from './typeDefs'
import { resolvers } from './resolvers'
import { verify } from 'jsonwebtoken'
import { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } from './constants'
import { User } from './entity/User'
import { createTokens } from './auth'

const startServer = async () => {
  const server = new ApolloServer({
    // These will be defined for both new or existing servers
    typeDefs,
    resolvers,
    context: ({ req, res }: any) => ({ req, res }),
  })

  await createConnection()

  const app = express()

  app.use(cookieParser())

  app.use(async (req: any, res, next) => {
    const refreshToken = req.cookies['refresh-token']
    const accessToken = req.cookies['access-token']
    if (!refreshToken && !accessToken) return next()

    try {
      const data = verify(accessToken, ACCESS_TOKEN_SECRET) as any
      req.userId = data.userId
      return next()
    } catch (error) {
      console.log('invalid access token')
      if (!refreshToken) return next()
    }

    let data
    try {
      data = verify(refreshToken, REFRESH_TOKEN_SECRET) as any
    } catch (error) {
      console.log('invalid refresh token')
      return next()
    }

    const user = await User.findOne(data.userId)
    if (!user || user.count !== data.count) {
      console.log('count different. cannot refresh token')
      return next()
    }

    console.log('refreshing token')
    const newTokens = createTokens(user)

    res.cookie('refresh-token', newTokens.refreshToken, {
      maxAge: 1000 * 60 * 60 * 24 * 7,
    })
    res.cookie('access-token', newTokens.accessToken, {
      maxAge: 1000 * 60 * 15,
    })
    req.userId = user.id
    next()
  })

  server.applyMiddleware({ app }) // app is from an existing express app

  app.listen({ port: 4000 }, () =>
    console.log(`🚀 Server ready at http://localhost:4000${server.graphqlPath}`)
  )
}

startServer()
