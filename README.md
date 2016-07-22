# jenkins-vault-plugin

This plugin adds a build wrapper to set environment variables from a HashiCorp [Vault](https://www.vaultproject.io/) secret.

## Build Wrapper Usage

The Vault plugin allows you to define the vault server URL as well as the root token via global configuration.

![Global Configuration][global_configuration]

Then in your job in the under **Build Environment** you check off **Vault Plugin** and configure the path to the secret in vault, the key of the secret, and the environment variable to set with its value.

![Job Configuration][job_configuration]

Here you can also override the vault server URL and token.

## Usage with a Jenkinsfile

This plugin also supports using a Jenkinsfile via the [Pipeline Plugin](https://wiki.jenkins-ci.org/display/JENKINS/Pipeline+Plugin)

```groovy
node {
  def secrets = [
    [$class: 'VaultSecret', path: 'secret/testing', secret: 'value', envVar: 'test_secret'],
    [$class: 'VaultSecret', path: 'secret/testingagain', secret: 'value', envVar: 'test_again']
  ]
  wrap([$class: 'VaultBuildWrapper', vaultSecrets: secrets]) {
      stage "first"
      sh 'echo "test_secret: ${test_secret}"'

      stage "second"
      sh 'echo "test_again: ${test_again}"'
  }
}
```

## TODO

* Refactor **VaultSecret** so it truly reflects a secret in vault.
* Add a [BuildStep](http://javadoc.jenkins-ci.org/hudson/tasks/BuildStep.html) for use as an alternative to the Build Wrapper.

[global_configuration]: docs/images/global_configuration.png
[job_configuration]: docs/images/job_configuration.png
