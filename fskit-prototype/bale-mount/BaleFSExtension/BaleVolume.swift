import FSKit
import Foundation

// Read-only FSVolume backed by the Rust VFS via the C FFI (bale_mount.h, exposed
// through the bridging header). FSKit has no "read-only conformance": the mutating
// ops are required protocol members, so we implement them as EROFS rejections.

@available(macOS 15.4, *)
private func posixError(_ code: Int32) -> NSError {
    NSError(domain: NSPOSIXErrorDomain, code: Int(code), userInfo: nil)
}

// FSItem carrying the Rust inode it stands for. FSKit owns FSItem lifetimes;
// we attach our identity so callbacks can map back to the VFS.
@available(macOS 15.4, *)
final class BaleItem: FSItem {
    let inode: UInt64
    let name: String
    init(inode: UInt64, name: String) {
        self.inode = inode
        self.name = name
        super.init()
    }
}

@available(macOS 15.4, *)
final class BaleVolume: FSVolume {
    private let vfs: OpaquePointer            // BaleVfs* from bale_vfs_open
    private let root: BaleItem

    init(vfs: OpaquePointer, volumeID: FSVolume.Identifier, volumeName: FSFileName) {
        self.vfs = vfs
        self.root = BaleItem(inode: UInt64(BALE_ROOT_INODE), name: "")
        super.init(volumeID: volumeID, volumeName: volumeName)
    }

    private func attrs(for inode: UInt64) -> FSItem.Attributes? {
        var a = BaleAttr()
        guard bale_vfs_getattr(vfs, inode, &a) == 0 else { return nil }
        let out = FSItem.Attributes()
        out.type = (a.kind == 0) ? .directory : .file
        out.size = a.size
        out.allocSize = a.size
        out.linkCount = 1
        out.fileID = FSItem.Identifier(rawValue: inode) ?? .invalid
        out.mode = (a.kind == 0) ? 0o555 : 0o444   // read-only
        return out
    }
}

// MARK: - pathconf

@available(macOS 15.4, *)
extension BaleVolume: FSVolume.PathConfOperations {
    var maximumLinkCount: Int { 1 }
    var maximumNameLength: Int { 255 }
    var restrictsOwnershipChanges: Bool { true }
    var truncatesLongNames: Bool { false }
}

// MARK: - core operations

@available(macOS 15.4, *)
extension BaleVolume: FSVolume.Operations {
    var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        let caps = FSVolume.SupportedCapabilities()
        caps.supportsHardLinks = false
        caps.supportsSymbolicLinks = false
        caps.supportsPersistentObjectIDs = true
        caps.doesNotSupportVolumeSizes = true
        return caps
    }

    var volumeStatistics: FSStatFSResult {
        let s = FSStatFSResult(fileSystemTypeName: "balefs")
        s.blockSize = 4096
        s.ioSize = 1 << 20
        return s
    }

    func activate(options: FSTaskOptions) async throws -> FSItem { root }

    func deactivate(options: FSDeactivateOptions = []) async throws {}

    func mount(options: FSTaskOptions) async throws {}

    func unmount() async {}

    func synchronize(flags: FSSyncFlags) async throws {}

    func attributes(_ request: FSItem.GetAttributesRequest, of item: FSItem) async throws -> FSItem.Attributes {
        guard let it = item as? BaleItem, let a = attrs(for: it.inode) else {
            throw posixError(ENOENT)
        }
        return a
    }

    func setAttributes(_ request: FSItem.SetAttributesRequest, on item: FSItem) async throws -> FSItem.Attributes {
        throw posixError(EROFS)
    }

    func lookupItem(named name: FSFileName, inDirectory directory: FSItem) async throws -> (FSItem, FSFileName) {
        guard let dir = directory as? BaleItem else { throw posixError(ENOENT) }
        let nameStr = name.string ?? ""
        let inode = nameStr.withCString { bale_vfs_lookup(vfs, dir.inode, $0) }
        guard inode != 0 else { throw posixError(ENOENT) }
        return (BaleItem(inode: inode, name: nameStr), name)
    }

    func reclaimItem(_ item: FSItem) async throws {}

    func readSymbolicLink(_ item: FSItem) async throws -> FSFileName {
        throw posixError(EINVAL)   // no symlinks in the prototype tree
    }

    func enumerateDirectory(
        _ directory: FSItem,
        startingAt cookie: FSDirectoryCookie,
        verifier: FSDirectoryVerifier,
        attributes: FSItem.GetAttributesRequest?,
        packer: FSDirectoryEntryPacker
    ) async throws -> FSDirectoryVerifier {
        guard let dir = directory as? BaleItem else { throw posixError(ENOENT) }

        final class Box { var entries: [(String, UInt64, Int32)] = [] }
        let box = Box()
        let ctx = Unmanaged.passUnretained(box).toOpaque()
        let cb: BaleDirCb = { ctx, namePtr, inode, kind in
            guard let ctx, let namePtr else { return }
            let b = Unmanaged<Box>.fromOpaque(ctx).takeUnretainedValue()
            b.entries.append((String(cString: namePtr), inode, kind))
        }
        _ = bale_vfs_readdir(vfs, dir.inode, cb, ctx)

        var next: FSDirectoryCookie = cookie
        for (name, inode, kind) in box.entries {
            next = FSDirectoryCookie(rawValue: next.rawValue + 1)
            let itemType: FSItem.ItemType = (kind == 0) ? .directory : .file
            let id = FSItem.Identifier(rawValue: inode) ?? .invalid
            _ = packer.packEntry(
                name: FSFileName(string: name),
                itemType: itemType,
                itemID: id,
                nextCookie: next,
                attributes: attributes != nil ? attrs(for: inode) : nil
            )
        }
        return verifier
    }

    // Mutating ops: read-only volume rejects them.
    func createItem(named name: FSFileName, type: FSItem.ItemType, inDirectory directory: FSItem, attributes newAttributes: FSItem.SetAttributesRequest) async throws -> (FSItem, FSFileName) {
        throw posixError(EROFS)
    }
    func createSymbolicLink(named name: FSFileName, inDirectory directory: FSItem, attributes newAttributes: FSItem.SetAttributesRequest, linkContents contents: FSFileName) async throws -> (FSItem, FSFileName) {
        throw posixError(EROFS)
    }
    func createLink(to item: FSItem, named name: FSFileName, inDirectory directory: FSItem) async throws -> FSFileName {
        throw posixError(EROFS)
    }
    func removeItem(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem) async throws {
        throw posixError(EROFS)
    }
    func renameItem(_ item: FSItem, inDirectory sourceDirectory: FSItem, named sourceName: FSFileName, to destinationName: FSFileName, inDirectory destinationDirectory: FSItem, overItem: FSItem?) async throws -> FSFileName {
        throw posixError(EROFS)
    }
}

// MARK: - open/close

@available(macOS 15.4, *)
extension BaleVolume: FSVolume.OpenCloseOperations {
    func openItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {}
    func closeItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {}
}

// MARK: - read (write rejected)

@available(macOS 15.4, *)
extension BaleVolume: FSVolume.ReadWriteOperations {
    func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer) async throws -> Int {
        guard let it = item as? BaleItem else { throw posixError(ENOENT) }
        let fh = bale_vfs_open_file(vfs, it.inode)
        guard fh != 0 else { throw posixError(EIO) }
        defer { bale_vfs_close(vfs, fh) }
        return buffer.withUnsafeMutableBytes { raw -> Int in
            let want = min(length, raw.count)
            let n = bale_vfs_read(vfs, fh, UInt64(offset), raw.baseAddress!.assumingMemoryBound(to: UInt8.self), want)
            return n < 0 ? 0 : Int(n)
        }
    }

    func write(contents: Data, to item: FSItem, at offset: off_t) async throws -> Int {
        throw posixError(EROFS)
    }
}
