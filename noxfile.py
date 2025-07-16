import os
import random
import shlex
import tempfile
from pathlib import Path

import nox

numprocesses = max(min(os.cpu_count() // 4, 12), 1)

django_env = {
    'DJANGO_SETTINGS_MODULE': 'authentic2.settings',
}

tests_targets = {
    'debian-bookworm': {
        'deps': [
            # Use versions from Debian or EO repositories
            'django==4.2.18',
            'django-model-utils>=4.2,<4.3',
            'django-select2==7.10.0',
            'django-tables2==2.4.1',
            'django-import-export==3.0.2',
            'djangorestframework==3.14.0',
            'git+https://github.com/latchset/jwcrypto.git@v1.1.0',
        ],
    },
    # Test against the latest version constraints from setup.py
    'latest-versions': {
        'deps': [
            'zxcvbn@git+https://github.com/dwolfhub/zxcvbn-python.git@v4.5.0',
        ],
    },
}

nox.options.keywords = 'ci or (debian and bookworm)'
nox.options.reuse_venv = True


@nox.session(reuse_venv=True)
@nox.parametrize(
    'target',
    list(tests_targets),
)
def tests(session, target):
    other_constraints = tests_targets.get(target, {}).get('deps', [])

    # install:
    # 1. first the dependencies for the tests
    # 2. local repository with links (developer mode)
    # 3. finally specific constraints for the test target
    session.install(
        '-r', 'test_requirements.txt', '-e', '.', *(other_constraints or []), silent=session.interactive
    )
    getlasso3(session)

    with session.chdir('src'):
        session.run('../manage.py', 'compilemessages', external=True, silent=True)

    session.log('Checking migrations...')
    check_migrations(session)

    session.log('Running pytest...')
    args = ['py.test', '-c', '.pytestrc']

    try:
        session.posargs.pop(session.posargs.index('--no-random-order'))
        random_order = False
    except ValueError:
        random_order = True

    if random_order:
        args.append('--random-order')
        for arg in session.posargs:
            if arg.startswith('--random-order-seed='):
                break
        else:
            arg = '--random-order-seed=%s' % random.randint(0, 0xFFFFFFFF)
            args.append(arg)
        for arg in session.posargs:
            if arg.startswith('--random-order-bucket='):
                break
        else:
            args.append('--random-order-bucket=global')

    coverage = False
    if not session.interactive:
        coverage = True
        args += ['-v', '--numprocesses', str(numprocesses)]
        args += ['-o', f'junit_suite_name={session.name}', f'--junit-xml=junit-{session.name}.xml']
    elif session.posargs:
        if '--coverage' in session.posargs:
            coverage = True
            while '--coverage' in session.posargs:
                session.posargs.remove('--coverage')
        args += session.posargs

    if coverage:
        args += [
            '--cov',
            '--cov-append',
            '--cov-report',
            'xml',
            '--cov-report',
            'html',
            '--cov-report',
            'lcov:coverage.info',
            '--cov-context=test',
        ]

        args += ['tests/']
    session.run(
        *args,
        env={
            **django_env,
            'AUTHENTIC2_SETTINGS_FILE': 'tests/settings.py',
        },
    )
    if coverage:
        if not os.path.isdir('diff-cover'):
            os.mkdir('diff-cover')
        diff_cover_cmd = shlex.join(
            [
                'diff-cover',
                'coverage.info',
                '--html-report',
                'diff-cover/diff-cover.html',
                '--external-css-file',
                'diff-cover/diff-cover.css',
                '--fail-under',
                '100',
            ],
        )
        diff_cover_status_json = 'diff_cover_status.json'
        session.run(
            '/bin/sh',
            '-c',
            '{ %s && echo -n 0 >&3 || { echo -n 1 >&3; false; }; } 3> %s'
            % (diff_cover_cmd, diff_cover_status_json),
            external=True,
        )


@nox.session(tags=['ci'], reuse_venv=True)
def codestyle(session):
    session.install('pre-commit')
    session.run('pre-commit', 'run', '--all-files', '--show-diff-on-failure', silent=not session.interactive)


@nox.session(tags=['ci'], reuse_venv=True)
def pylint(session):
    session.install('-e', '.', 'pylint', 'pylint-django', '-r', 'test_requirements.txt')
    getlasso3(session)

    args = session.posargs or ['src/', 'tests/', 'noxfile.py']
    pylint_command = [
        'pylint',
        '--jobs',
        str(numprocesses),
        '-f',
        'parseable',
        '--rcfile',
        '.pylintrc',
        *args,
    ]

    session.run(
        'bash',
        '-c',
        f'{shlex.join(pylint_command)} | tee pylint.out ; test $PIPESTATUS -eq 0',
        external=True,
        silent=not session.interactive,
    )


@nox.session(reuse_venv=True)
def manage(session):
    session.install('-e', '.', 'psycopg2_binary', 'django-debug-toolbar', 'ipython', 'ipdb')
    getlasso3(session)

    session.run(
        './manage.py', *session.posargs, external=True, env={'AUTHENTIC2_SETTINGS_FILE': 'local_settings.py'}
    )


@nox.session(name='update-locales', reuse_venv=True)
def update_locales(session):
    session.install('-e', '.', 'psycopg2_binary')
    getlasso3(session)

    session.run(
        './manage.py',
        'makemessages',
        '-l',
        'fr',
        '-i',
        'tests',
        external=True,
    )
    with session.chdir('src'):
        session.run('../manage.py', 'compilemessages', external=True)


@nox.session(tags=['ci'], reuse_venv=True)
def check_manifest(session):
    # django is only required to compile messages
    session.install('django', 'check-manifest')
    # compile messages and css
    ignores = [
        'VERSION',
        'src/authentic2/manager/static/authentic2/manager/css/*.css',
        'src/authentic2/static/authentic2/css/*.css',
        'src/authentic2/static/css/*.css',
        'src/authentic2_idp_oidc/static/authentic2_idp_oidc/css/*.css',
    ]
    session.run('check-manifest', '--ignore', ','.join(ignores))


###########
# helpers #
###########


def getlasso3(session):
    src_dir = Path('/usr/lib/python3/dist-packages/')
    venv_dir = Path(session.virtualenv.location)
    for dst_dir in venv_dir.glob('lib/**/site-packages'):
        files_to_link = [src_dir / 'lasso.py'] + list(src_dir.glob('_lasso.cpython-*.so'))

        for src_file in files_to_link:
            dst_file = dst_dir / src_file.name
            if dst_file.exists():
                dst_file.unlink()
            dst_file.symlink_to(src_file)


def check_migrations(session):
    with tempfile.NamedTemporaryFile(mode='w') as fd:
        print(
            '''\
import django
from django.apps import apps
from django.conf import settings
from django.core.management import call_command

settings.DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.dummy',
    }
}

django.setup()

app_labels = [app.label for app in apps.get_app_configs() if app.label not in ['admin', 'auth', 'contenttypes']]

call_command('makemigrations', *app_labels, dry_run=True, no_input=True, verbosity=1, check=True)
''',
            file=fd,
            flush=True,
        )
        session.run('python3', fd.name, env=django_env, silent=True)
