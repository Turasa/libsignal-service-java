dependencyResolutionManagement {
  versionCatalogs {
    create("libs") {
      version("libsignal-client", "0.58.2")

      // Kotlin
      version("kotlin", "1.9.20")
      library("kotlin-stdlib-jdk8", "org.jetbrains.kotlin", "kotlin-stdlib-jdk8").versionRef("kotlin")
      library("kotlin-reflect", "org.jetbrains.kotlin", "kotlin-reflect").versionRef("kotlin")
      library("ktlint", "org.jlleitschuh.gradle:ktlint-gradle:12.1.1")
      library("kotlinx-coroutines-core", "org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
      library("kotlinx-coroutines-core-jvm", "org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.9.0")

      // Google
      library("google-libphonenumber", "com.googlecode.libphonenumber:libphonenumber:8.13.40")
      library("google-jsr305", "com.google.code.findbugs:jsr305:3.0.2")

      // 1st Party
      library("libsignal-client", "org.signal", "libsignal-client").versionRef("libsignal-client")

      // Third Party
      library("jackson-core", "com.fasterxml.jackson.core:jackson-databind:2.17.1")
      library("jackson-module-kotlin", "com.fasterxml.jackson.module:jackson-module-kotlin:2.17.1")
      library("square-okhttp3", "com.squareup.okhttp3:okhttp:4.12.0")
      library("square-okio", "com.squareup.okio:okio:3.9.0")
      library("rxjava3-rxjava", "io.reactivex.rxjava3:rxjava:3.0.13")
    }

    create("testLibs") {
      library("junit-junit", "junit:junit:4.13.2")
      library("kotlinx-coroutines-test", "org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
      library("mockito-core", "org.mockito:mockito-core:2.23.4")
      library("assertj-core", "org.assertj:assertj-core:3.11.1")
      library("conscrypt-openjdk-uber", "org.conscrypt:conscrypt-openjdk-uber:2.5.2")
      library("mockk", "io.mockk:mockk:1.13.2")
    }
  }
}
