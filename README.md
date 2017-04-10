# jenkins-vault-plugin

This plugin adds a build wrapper to set environment variables from a HashiCorp [Vault](https://www.vaultproject.io/) secret.

## Caveats

If using the AWS secret backend for vault you need to make sure you give some time for the IAM credentials to become active (unless using STS). For example, a build job may look like the following:

```
sleep 5 && aws ec2 describe-instances
```

## Build Wrapper Usage

The Vault plugin allows you to define the vault server URL as well as a credential for the root token OR a path to a file that contains the token. If a credential is specified then the file will not be used.

![Global Configuration][global_configuration]

Then in your job in the under **Build Environment** you check off **Vault Plugin** and configure the path to the secret in vault, and add key/value pairs to set environment variables with the values of keys in the vault path.

![Job Configuration][job_configuration]

Here you can also override the vault server URL and token. (This is currently broken: [JENKINS-37203](https://issues.jenkins-ci.org/browse/JENKINS-37203))

## Usage with a Jenkinsfile

This plugin also supports using a Jenkinsfile via the [Pipeline Plugin](https://wiki.jenkins-ci.org/display/JENKINS/Pipeline+Plugin)

```groovy
node {
  def secrets = [
      [$class: 'VaultSecret', path: 'secret/testing', secretValues: [
          [$class: 'VaultSecretValue', envVar: 'testing', vaultKey: 'value_one'],
          [$class: 'VaultSecretValue', envVar: 'testing_again', vaultKey: 'value_two']]],
      [$class: 'VaultSecret', path: 'secret/another_test', secretValues: [
          [$class: 'VaultSecretValue', envVar: 'another_test', vaultKey: 'value']]]
  ]

  wrap([$class: 'VaultBuildWrapper', vaultSecrets: secrets]) {
      sh 'echo $testing'
      sh 'echo $testing_again'
      sh 'echo $another_test'
  }
}
```

## TODO

* [JENKINS-37203 - Override Authentication Token?" do not work](https://issues.jenkins-ci.org/browse/JENKINS-37203)
* Add a [BuildStep](http://javadoc.jenkins-ci.org/hudson/tasks/BuildStep.html) for use as an alternative to the Build Wrapper.

## CHANGELOG

* **2017/04/10** - Feature Release - 1.4
  * Support reading Vault Token from file on disk [JENKINS-37713](issues.jenkins-ci.org/browse/JENKINS-37713)
  * Using credentials plugin for authentication token [JENKINS-38646](issues.jenkins-ci.org/browse/JENKINS-38646)
* **2017/03/03** - Feature Release - 1.3
  * Vault Plugin should mask credentials in build log [JENKINS-39383](issues.jenkins-ci.org/browse/JENKINS-39383)
* **2016/08/15** - Re-release due to failed maven release - 1.2
* **2016/08/11** - Bugfix release - 1.1
  * Refactor to allow getting multiple vault keys in a single API call [JENKINS-37151](https://issues.jenkins-ci.org/browse/JENKINS-37151)
* **2016/08/02** - Initial release - 1.0

[global_configuration]: docs/images/global_configuration.png
[job_configuration]: docs/images/job_configuration.png
