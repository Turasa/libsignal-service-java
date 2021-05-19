import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  alias(libs.plugins.jetbrains.kotlin.jvm) apply false
}

val signalKotlinJvmTarget: String by rootProject.extra

buildscript {
  repositories {
    google()
    mavenCentral()
    maven {
      url = uri("https://plugins.gradle.org/m2/")
      content {
        includeGroupByRegex("org\\.jlleitschuh\\.gradle.*")
      }
    }
  }
  dependencies {
    classpath("com.squareup.wire:wire-gradle-plugin:4.4.3") {
      exclude(group = "com.squareup.wire", module = "wire-swift-generator")
      exclude(group = "com.squareup.wire", module = "wire-grpc-client")
      exclude(group = "com.squareup.wire", module = "wire-grpc-jvm")
      exclude(group = "com.squareup.wire", module = "wire-grpc-server-generator")
      exclude(group = "io.outfoxx", module = "swiftpoet")
    }
    classpath(files("$rootDir/wire-handler/wire-handler-1.0.0.jar"))
  }
}

apply(from = "${rootDir}/constants.gradle.kts")

val lib_signal_service_version_number: String by rootProject.extra
val lib_signal_service_group_info: String by rootProject.extra

allprojects {
  version = lib_signal_service_version_number
  group = lib_signal_service_group_info

  // Needed because otherwise the kapt task defaults to jvmTarget 17, which "poisons the well" and requires us to bump up too
  tasks.withType<KotlinCompile>().configureEach {
    compilerOptions {
      jvmTarget = JvmTarget.fromTarget(signalKotlinJvmTarget)
    }
  }
  tasks.withType<Jar>().configureEach {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
  }
}

subprojects {
  if (JavaVersion.current().isJava8Compatible) {
    allprojects {
      tasks.withType<Javadoc>() {
        (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:none", "-quiet")
      }
    }
  }
}
