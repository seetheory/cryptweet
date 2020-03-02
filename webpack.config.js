const webpack = require('webpack')
const path = require('path')

module.exports = {
  mode: 'development',
  entry: ['./src/twitter.js'],
  output: {
    filename: 'twitter.js',
    path: path.resolve(__dirname, 'build'),
  },
  resolve: {
    extensions: ['.js'],
  },
}
