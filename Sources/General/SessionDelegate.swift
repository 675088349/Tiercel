//
//  SessionDelegate.swift
//  Tiercel
//
//  Created by Daniels on 2018/3/16.
//  Copyright © 2018 Daniels. All rights reserved.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import Foundation
import Security

internal class SessionDelegate: NSObject {
    internal weak var manager: SessionManager?

    private func handleServerTrust(
        challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust,
              let origin = Self.origin(for: challenge.protectionSpace) else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        if SecTrustEvaluateWithError(serverTrust, nil) {
            completionHandler(.performDefaultHandling, nil)
        } else if manager?.configuration.allowedUntrustedTLSOrigins.contains(origin) == true {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else if let challengeHandler = manager?.configuration.untrustedTLSChallengeHandler {
            // 让宿主展示确认后直接恢复同一条 Tiercel 任务，
            // 不再先失败、丢失任务上下文后再依赖页面重试。
            challengeHandler(origin) { isApproved in
                if isApproved {
                    completionHandler(.useCredential, URLCredential(trust: serverTrust))
                } else {
                    completionHandler(.performDefaultHandling, nil)
                }
            }
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }

    private static func origin(for protectionSpace: URLProtectionSpace) -> String? {
        guard protectionSpace.protocol?.lowercased() == "https",
              !protectionSpace.host.isEmpty else { return nil }
        var components = URLComponents()
        components.scheme = "https"
        components.host = protectionSpace.host.lowercased()
        components.port = protectionSpace.port > 0 ? protectionSpace.port : 443
        return components.string
    }
}


extension SessionDelegate: URLSessionDownloadDelegate {
    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handleServerTrust(challenge: challenge, completionHandler: completionHandler)
    }

    public func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handleServerTrust(challenge: challenge, completionHandler: completionHandler)
    }

    public func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) {
        manager?.didBecomeInvalidation(withError: error)
    }
    
    
    public func urlSessionDidFinishEvents(forBackgroundURLSession session: URLSession) {
        manager?.didFinishEvents(forBackgroundURLSession: session)
    }
    
    
    public func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64, totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        guard let manager = manager else { return }
        guard let currentURL = downloadTask.currentRequest?.url else { return }
        guard let task = manager.mapTask(currentURL) else {
            manager.log(.error("urlSession(_:downloadTask:didWriteData:totalBytesWritten:totalBytesExpectedToWrite:)",
                               error: TiercelError.fetchDownloadTaskFailed(url: currentURL))
                        )
            return
        }
        task.didWriteData(downloadTask: downloadTask, bytesWritten: bytesWritten, totalBytesWritten: totalBytesWritten, totalBytesExpectedToWrite: totalBytesExpectedToWrite)
    }
    
    
    public func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        guard let manager = manager else { return }
        guard let currentURL = downloadTask.currentRequest?.url else { return }
        guard let task = manager.mapTask(currentURL) else {
            manager.log(.error("urlSession(_:downloadTask:didFinishDownloadingTo:)", error: TiercelError.fetchDownloadTaskFailed(url: currentURL)))
            return
        }
        task.didFinishDownloading(task: downloadTask, to: location)
    }
    
    public func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let manager = manager else { return }
        if let currentURL = task.currentRequest?.url {
            guard let downloadTask = manager.mapTask(currentURL) else {
                manager.log(.error("urlSession(_:task:didCompleteWithError:)", error: TiercelError.fetchDownloadTaskFailed(url: currentURL)))
                return
            }
            downloadTask.didComplete(.network(task: task, error: error))
        } else {
            if let error = error {
                if let urlError = error as? URLError,
                    let errorURL = urlError.userInfo[NSURLErrorFailingURLErrorKey] as? URL {
                    guard let downloadTask = manager.mapTask(errorURL) else {
                        manager.log(.error("urlSession(_:task:didCompleteWithError:)", error: TiercelError.fetchDownloadTaskFailed(url: errorURL)))
                        manager.log(.error("urlSession(_:task:didCompleteWithError:)", error: error))
                        return
                    }
                    downloadTask.didComplete(.network(task: task, error: error))
                } else {
                    manager.log(.error("urlSession(_:task:didCompleteWithError:)", error: error))
                    return
                }
            } else {
                manager.log(.error("urlSession(_:task:didCompleteWithError:)", error: TiercelError.unknown))
            }
        }
    }
}
