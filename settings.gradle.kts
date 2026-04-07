dependencyResolutionManagement {
  repositories {
    mavenCentral()
    mavenLocal()
    maven {
      name = "SignalBuildArtifacts"
      url = uri("https://build-artifacts.signal.org/libraries/maven/")
      content {
        includeGroupByRegex("org\\.signal.*")
      }
    }
  }
  versionCatalogs {
    // libs.versions.toml is automatically registered.
    create("testLibs") {
      from(files("gradle/test-libs.versions.toml"))
    }
  }
}

include(":lib:libsignal-service")
project(":lib:libsignal-service").projectDir = file("service")

include(":lib:network")
project(":lib:network").projectDir = file("network")

include(":core:util-jvm")
project(":core:util-jvm").projectDir = file("core-util-jvm")

include(":core:models-jvm")
project(":core:models-jvm").projectDir = file("core-models-jvm")
