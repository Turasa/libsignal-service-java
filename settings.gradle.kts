dependencyResolutionManagement {
  repositories {
    mavenCentral()
    mavenLocal()
  }
  versionCatalogs {
    // libs.versions.toml is automatically registered.
    create("testLibs") {
      from(files("gradle/test-libs.versions.toml"))
    }
  }
}

include("libsignal-service")
project(":libsignal-service").projectDir = file("service")

include(":core-util-jvm")
