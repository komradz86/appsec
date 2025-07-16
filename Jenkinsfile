@Library('eo-jenkins-lib@main') import eo.Utils

pipeline {
    agent any
    options { disableConcurrentBuilds() }
    parameters {
        choice(name: 'deps_version',
               choices: ['latest', 'bookworm', 'both'],
               description: "Select dependencies for the tests (latest = django4, bookworm=django3, latest or bookworm = both")
    }
    triggers {
        // run all tests targets at chosen times
        cron('H 7,10,13,16 * * 1-5')
    }
    stages {
        stage('Unit Tests (latest)') {
            when { expression { params.deps_version == 'latest' || params.deps_version == 'both' } }
            steps {
                sh """PGPORT=`python3 -c 'import struct; import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); s.bind(("", 0)); print(s.getsockname()[1]); s.close()'` pg_virtualenv -o fsync=off nox -N -k "latest" """
            }
            post {
                always {
                    script {
                        def utils = new Utils()
                        utils.publish_coverage('coverage.xml')
                        utils.publish_coverage_native()
                        utils.publish_diff_cover()
                        utils.display_diff_cover_status()
                    }
                    mergeJunitResults()
                }
            }
        }
        stage('Unit Tests (bookworm)') {
            when { expression { params.deps_version == 'bookworm' || params.deps_version == 'both' || currentBuild.getBuildCauses('hudson.triggers.TimerTrigger$TimerTriggerCause') } }
            steps {
                sh """PGPORT=`python3 -c 'import struct; import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); s.bind(("", 0)); print(s.getsockname()[1]); s.close()'` pg_virtualenv -o fsync=off nox -N -k "bookworm" """
            }
            post {
                always {
                    script {
                        def utils = new Utils()
                        utils.publish_coverage('coverage.xml')
                        utils.publish_coverage_native()
                        // no diff-cover if not latest
                    }
                    mergeJunitResults()
                }
            }
        }
	stage('codestyle') {
		steps {
		    sh """nox -N -k "ci" """
		}
		post {
		    always { script {
                        def utils = new Utils()
                        utils.publish_pylint('pylint.out')
                    }}
		}
	}
        stage('Packaging') {
            steps {
                script {
                    env.SHORT_JOB_NAME=sh(
                        returnStdout: true,
                        // given JOB_NAME=gitea/project/PR-46, returns project
                        // given JOB_NAME=project/main, returns project
                        script: '''
                            echo "${JOB_NAME}" | sed "s/gitea\\///" | awk -F/ '{print $1}'
                        '''
                    ).trim()
                    if (env.GIT_BRANCH == 'main' || env.GIT_BRANCH == 'origin/main') {
                        sh "sudo -H -u eobuilder /usr/local/bin/eobuilder -d bookworm ${SHORT_JOB_NAME}"
                    } else if (env.GIT_BRANCH.startsWith('hotfix/')) {
                        sh "sudo -H -u eobuilder /usr/local/bin/eobuilder -d bookworm --branch ${env.GIT_BRANCH} --hotfix ${SHORT_JOB_NAME}"
                    }
                }
            }
        }
    }
    post {
        always {
            script {
                def utils = new Utils()
                utils.mail_notify(currentBuild, env, 'ci+jenkins-authentic@entrouvert.org')
            }
        }
        cleanup {
            cleanWs()
        }
    }
}
// vim: expandtab tabstop=4 shiftwidth=4
