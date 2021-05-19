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

include("signal-service-java")
project(":signal-service-java").projectDir = file("service")

include(":core-util-jvm")
