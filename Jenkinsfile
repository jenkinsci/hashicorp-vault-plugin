def recentLTS = "2.222.1"
def configurations = [
    [ platform: "linux", jdk: "8", jenkins: null ],
    [ platform: "linux", jdk: "8", jenkins: recentLTS ],
    [ platform: "linux", jdk: "11", jenkins: null, javaLevel: "8" ],
    [ platform: "linux", jdk: "11", jenkins: recentLTS, javaLevel: "8" ],
]
buildPlugin(configurations: configurations, findbugs: [archive: true])
