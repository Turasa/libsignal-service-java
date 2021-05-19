/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  id("java-library")
  id("org.jetbrains.kotlin.jvm")
  id("idea")
  id("maven-publish")
  id("signing")
  alias(libs.plugins.ktlint)
}

java {
  withJavadocJar()
  withSourcesJar()
  sourceCompatibility = JavaVersion.toVersion(libs.versions.javaVersion.get())
  targetCompatibility = JavaVersion.toVersion(libs.versions.javaVersion.get())
}

tasks.withType<KotlinCompile>().configureEach {
  kotlin {
    compilerOptions {
      jvmTarget = JvmTarget.fromTarget(libs.versions.kotlinJvmTarget.get())
      freeCompilerArgs = listOf("-Xjvm-default=all")
      suppressWarnings = true
    }
  }
}

ktlint {
  version.set("1.5.0")
}

tasks.whenTaskAdded {
  if (name == "lint") {
    enabled = false
  }
}

dependencies {
  api(project(":lib:libsignal-service"))

  implementation(libs.libsignal.client)
  api(libs.square.okhttp3)
  api(libs.square.okio)

  api(libs.rxjava3.rxjava)
  implementation(libs.rxjava3.rxkotlin)

  implementation(libs.kotlin.stdlib.jdk8)
  implementation(libs.kotlinx.coroutines.core)
  implementation(libs.kotlinx.coroutines.core.jvm)

  implementation(project(":core:util-jvm"))
  implementation(project(":core:models-jvm"))

  testImplementation(testLibs.junit.junit)
  testImplementation(testLibs.assertk)
  testImplementation(testLibs.mockk)
}

publishing {
  publications {
    create<MavenPublication>("mavenJava") {
      from(components["java"])
      artifactId = "signal-network"

      pom {
        name.set("signal-network")
        description.set("Signal Service communication library for Java, unofficial fork")
        url.set("https://github.com/Turasa/libsignal-service-java")
        licenses {
          license {
            name.set("GPLv3")
            url.set("https://www.gnu.org/licenses/gpl-3.0.txt")
          }
        }
        developers {
          developer {
            name.set("Moxie Marlinspike")
          }
          developer {
            name.set("Sebastian Scheibner")
          }
          developer {
            name.set("Tilman Hoffbauer")
          }
        }
        scm {
          connection.set("scm:git@github.com:Turasa/libsignal-service-java.git")
          developerConnection.set("scm:git@github.com:Turasa/libsignal-service-java.git")
          url.set("scm:git@github.com:Turasa/libsignal-service-java.git")
        }
      }
    }
  }
}

signing {
  isRequired = gradle.taskGraph.hasTask("uploadArchives")
  sign(publishing.publications["mavenJava"])
}
