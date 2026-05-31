import FSKit
import Foundation

// The FSUnaryFileSystem delegate: probes/loads the resource and hands FSKit a
// BaleVolume. The "resource" is how the CLI passes context (repo + rev); here we
// accept it and call bale_vfs_open. In a real build the resource would carry the
// repo path + rev (e.g. via FSGenericURLResource or an FSPathURLResource).

@available(macOS 15.4, *)
final class BaleFS: FSUnaryFileSystem, FSUnaryFileSystemOperations {

    func probeResource(
        resource: FSResource,
        replyHandler reply: @escaping (FSProbeResult?, (any Error)?) -> Void
    ) {
        // A unary FS for synthetic content: claim the resource unconditionally.
        reply(FSProbeResult.usable(name: "balefs", containerID: FSContainerIdentifier()), nil)
    }

    func loadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler reply: @escaping (FSVolume?, (any Error)?) -> Void
    ) {
        // Prototype context. Real build: decode repo+rev from the resource.
        let vfs = "/tmp/some/repo".withCString { repo in
            "HEAD".withCString { rev in
                bale_vfs_open(repo, rev)
            }
        }
        guard let vfs else {
            reply(nil, NSError(domain: NSPOSIXErrorDomain, code: Int(EIO)))
            return
        }
        let volume = BaleVolume(
            vfs: vfs,
            volumeID: FSVolume.Identifier(uuid: UUID()),
            volumeName: FSFileName(string: "bale")
        )
        reply(volume, nil)
    }

    func unloadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler reply: @escaping ((any Error)?) -> Void
    ) {
        reply(nil)
    }
}

// AppExtension entry point. Built into the .appex; FSKit instantiates it.
@available(macOS 15.4, *)
@main
struct BaleFSExtension: UnaryFileSystemExtension {
    var fileSystem: BaleFS { BaleFS() }
}
