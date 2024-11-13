module.exports = {
    branches: ['main'],
    tagFormat: '${version}',
    plugins: [
        [
            '@semantic-release/commit-analyzer',
            {
                preset: 'angular',
                parserOpts: {
                    noteKeywords: ['BREAKING CHANGE', 'BREAKING CHANGES', 'BREAKING'],
                },
            },
        ],
        [
            '@semantic-release/release-notes-generator',
            {
                preset: 'angular',
                parserOpts: {
                    noteKeywords: ['BREAKING CHANGE', 'BREAKING CHANGES', 'BREAKING'],
                },
                writerOpts: {
                    commitsSort: ['subject', 'scope'],
                },
            },
        ],
        [
            '@semantic-release/exec',
            {
                prepareCmd: [
                    'poetry build --no-interaction',
                    'poetry publish --dry-run --no-interaction',
                    'rm -f CHANGELOG.md',
                    'poetry version ${nextRelease.version}',
                    'poetry export --without-hashes --format=requirements.txt --without dev -o requirements.txt',
                    'poetry export --without-hashes --format=requirements.txt --with dev -o requirements-dev.txt',
                ].join(' && '),
                successCmd:
                    'poetry publish --repository pypi',
            },
        ],
        [
            '@semantic-release/changelog',
            {
                changelogFile: 'CHANGELOG.md',
            },
        ],
        [
            '@semantic-release/git',
            {
                assets: ['CHANGELOG.md', 'pyproject.toml', 'requirements.txt', 'requirements-dev.txt'],
                message: 'chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}',
            },
        ],
    ],
};
