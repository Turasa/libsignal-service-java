/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.signalservice.api.push.exceptions

import java.io.IOException

/**
 * Indicates a server response that is not successful, typically something outside the 2xx range.
 */
open class NonSuccessfulResponseCodeException : IOException {
  @JvmField
  val code: Int
  val stringBody: String?
  val binaryBody: ByteArray?

  constructor(code: Int) : super("StatusCode: $code") {
    this.code = code
    this.stringBody = null
    this.binaryBody = null
  }

  constructor(code: Int, message: String) : super("[$code] $message") {
    this.code = code
    this.stringBody = null
    this.binaryBody = null
  }

  constructor(code: Int, message: String, body: String?) : super("[$code] $message") {
    this.code = code
    this.stringBody = body
    this.binaryBody = null
  }

  constructor(code: Int, message: String, body: ByteArray?) : super("[$code] $message") {
    this.code = code
    this.stringBody = null
    this.binaryBody = body
  }

  fun is4xx(): Boolean {
    return code >= 400 && code < 500
  }

  fun is5xx(): Boolean {
    return code >= 500 && code < 600
  }
}