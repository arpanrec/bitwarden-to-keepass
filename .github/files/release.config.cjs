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
            '@semantic-release/changelog',
            {
                changelogFile: 'CHANGELOG.md',
            },
        ],
        [
            '@semantic-release/exec',
            {
                prepareCmd: [
                    'rm -f CHANGELOG.md',
                    'poetry version ${nextRelease.version}',
                    'poetry export --without-hashes --format=requirements.txt -o requirements.txt',
                    'poetry export --without-hashes --format=requirements.txt --with dev -o requirements-dev.txt',
                ].join(' && '),
                // successCmd:
                //     'ansible-galaxy collection publish arpanrec-nebula-${nextRelease.version}.tar.gz --api-key ${process.env.GALAXY_API_KEY}',
            },
        ],
        [
            '@semantic-release/git',
            {
                assets: [
                    'CHANGELOG.md',
                    'pyproject.toml',
                    'requirements.txt',
                    'requirements-dev.txt',
                ],
                message: 'chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}',
            },
        ],
    ],
};
