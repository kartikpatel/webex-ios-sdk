// Copyright 2016 Cisco Systems Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import ObjectMapper

/// Represents a Spark call.
public class Call {
    
    /// Completion handler for a call operation.
    public typealias CompletionHandler = Bool -> Void
    
    /// Camera facing mode.
    public enum FacingMode: String {
        /// Front camera.
        case User
        /// Back camera.
        case Environment
    }
    
    /// Call status.
    public enum Status: String {
        /// Intended recipient hasn't accepted the call.
        case Initiated
        /// Remote party has acknowledged the call.
        case Ringing
        /// An incoming call from remote party.
        case Incoming
        /// Call gets connected.
        case Connected
        /// Call gets disconnected.
        case Disconnected
    }
    
    /// Call status.
    public var status: Status {
        return state.status
    }

    /// The intended recipient of the call. 
    /// For an outgoing call this is the same as the address specified in dial. 
    /// For an incoming call this is the identity of the authenticated user.
    public var to: String?
    
    /// The receiver of the call. 
    /// For an outgoing call this is the identity of the authenticated user.
    /// For an incoming call this is the email address / phone number / SIP address of the caller.
    public var from: String?
    
    /// True if client is sending audio.
    public var sendingAudio: Bool {
        return !mediaSession.audioMuted
    }
    
    /// True if client is receiving audio.
    public var receivingAudio: Bool {
        return !mediaSession.audioOutputMuted
    }
    
    /// True if client is sending video.
    public var sendingVideo: Bool {
        return mediaSession.hasVideo && !mediaSession.videoMuted
    }
    
    /// True if client is receiving video.
    public var receivingVideo: Bool {
        return mediaSession.hasVideo && !mediaSession.videoOutputMuted
    }
    
    /// True if remote is sending audio.
    public var remoteSendingAudio: Bool {
        if let info = self.info {
            return !info.remoteAudioMuted
        }
        return false
    }
    
    /// True if remote is sending video.
    public var remoteSendingVideo: Bool {
        if let info = self.info {
            return !info.remoteVideoMuted
        }
        return false
    }
    
    /// True if loud speaker is selected as the output device for this call.
    public var loudSpeaker: Bool {
        return mediaSession.isSpeakerSelected()
    }
    
    /// Camera facing mode selected for this call.
    public var facingMode: FacingMode {
        return mediaSession.isFrontCameraSelected() ? .User : .Environment
    }
    
    /// Local video render view height.
    public var localVideoViewHeight: UInt32 {
        return mediaSession.localVideoViewHeight
    }
    
    /// Local video render view width.
    public var localVideoViewWidth: UInt32 {
        return mediaSession.localVideoViewWidth
    }
    
    /// Remote video render view height.
    public var remoteVideoViewHeight: UInt32 {
        return mediaSession.remoteVideoViewHeight
    }
    
    /// Remote video render view width.
    public var remoteVideoViewWidth: UInt32 {
        return mediaSession.remoteVideoViewWidth
    }
    
    /// True if the DTMF keypad can be enabled for Client.
    public var sendingDTMFEnabled: Bool {
        if let enableDTMF = info?.enableDTMF {
            return enableDTMF
        } else {
            return false
        }
    }
    
    var info: CallInfo?
    var state: CallState!
    var url: String { return (info?.callUrl)! }
    
    private let mediaEngine = MediaEngineWrapper.sharedInstance
    private let mediaSession = MediaSessionWrapper()
    private let deviceUrl = DeviceService.sharedInstance.deviceUrl
    private let reachabilityService = ReachabilityService.sharedInstance
    private var dtmfQueue: DtmfQueue!
    
    init() {
        state = CallStateIdle(self)
        dtmfQueue = DtmfQueue(self)
    }
    
    init(_ info: CallInfo) {
        self.info = info
        to = info.selfEmail
        from = info.hostEmail
        
        state = CallStateIncoming(self)
        dtmfQueue = DtmfQueue(self)
    }
    
    /// Answers an incoming call. Only applies to incoming calls.
    ///
    /// - parameter option: Media option for call: audio-only, audio+video etc. If it contains video, need to specify render view for video.
    /// - parameter completionHandler: A closure to be executed once the action is completed. True means success, False means failure.
    /// - returns: Void
    /// - note: This function is expected to run on main thread.
    public func answer(option option: MediaOption, completionHandler: CompletionHandler?) {
        let answerAction: () -> Void = {
            self.prepareMediaSession(option)
            
            let localInfo = self.createLocalInfo(self.mediaSession.getLocalSdp())
            CallClient().join(self.url, localInfo: localInfo) {
                self.onJoinCallCompleted($0, completionHandler: completionHandler)
            }
        }
        
        doCallAction(answerAction, option: option, completionHandler: completionHandler)
    }
    
    /// Disconnects the active call. Applies to both incoming and outgoing calls.
    ///
    /// - parameter completionHandler: A closure to be executed once the action is completed. True means success, False means failure.
    /// - returns: Void
    /// - note: This function is expected to run on main thread.
    public func hangup(completionHandler: CompletionHandler?) {
        mediaSession.stopMedia()
        
        let participantUrl = info?.selfParticipantUrl
        CallClient().leave(participantUrl!, deviceUrl: deviceUrl!) {
            switch $0.result {
            case .Success(let value):
                self.updateCallInfo(value)
                Logger.info("Success: leave call")
                completionHandler?(true)
            case .Failure(let error):
                Logger.error("Failure: \(error.localizedFailureReason)")
                completionHandler?(false)
            }
        }
    }
    
    /// Rejects an incoming call. Only applies to incoming calls.
    ///
    /// - parameter completionHandler: A closure to be executed once the action is completed. True means success, False means failure.
    /// - returns: Void
    /// - note: This function is expected to run on main thread.
    public func reject(completionHandler: CompletionHandler?) {
        mediaSession.stopMedia()
        
        let callUrl = info?.callUrl
        CallClient().decline(callUrl!, deviceUrl: deviceUrl!) {
            switch $0.result {
            case .Success:
                Logger.info("Success: reject call")
                completionHandler?(true)
            case .Failure(let error):
                Logger.error("Failure: \(error.localizedFailureReason)")
                completionHandler?(false)
            }
        }
    }
    
    /// Sends DTMF events to remote destination.
    ///
    /// - parameter dtmf: Valid DTMF events. 0-9, *, #, and A-D.
    /// - parameter completionHandler: A closure to be executed once the action is completed. True means success, False means failure.
    /// - returns: Void
    /// - note: This function is expected to run on main thread.
    public func sendDTMF(dtmf: String, completionHandler: CompletionHandler?) {
        if sendingDTMFEnabled {
            dtmfQueue!.push(dtmf, completionHandler: completionHandler)
        } else {
            completionHandler?(false)
        }
    }
    
    /// If sending video then stop sending video. If not sending video then start sending video.
    ///
    /// - note: This function is expected to run on main thread.
    public func toggleSendingVideo() {
        mediaSession.toggleSendingVideo()
    }
    
    /// If receiving video then stop receiving video. If not receiving video then start receiving video.
    ///
    /// - note: This function is expected to run on main thread.
    public func toggleReceivingVideo() {
        mediaSession.toggleReceivingVideo()
    }
    
    /// If sending audio then stop sending audio. If not sending audio then start sending audio.
    ///
    /// - note: This function is expected to run on main thread.
    public func toggleSendingAudio() {
        mediaSession.toggleSendingAudio()
    }
    
    /// If receiving audio then stop receiving audio. If not receiving audio then start receiving audio.
    ///
    /// - note: This function is expected to run on main thread.
    public func toggleReceivingAudio() {
        mediaSession.toggleReceivingAudio()
    }
    
    /// Toggle camera facing mode between front camera and back camera.
    ///
    /// - note: This function is expected to run on main thread.
    public func toggleFacingMode() {
        mediaSession.toggleFacingMode()
    }
    
    /// Toggle loud speaker.
    ///
    /// - note: This function is expected to run on main thread.
    public func toggleLoudSpeaker() {
        mediaSession.toggleLoudSpeaker()
    }
    
    /// Send feed back to Spark.
    ///
    /// - parameter rating: Rating between 1 and 5.
    /// - parameter comments: User comments.
    /// - parameter includeLogs: True if to include logs, False as not.
    /// - returns: Void
    /// - note: This function is expected to run on main thread.
    public func sendFeedback(rating: Int, comments: String? = nil, includeLogs: Bool = false) {
        let feedback = Feedback(rating: rating, comments: comments, includeLogs: includeLogs)
        CallMetrics.sharedInstance.submitFeedback(feedback, callInfo: info!)
    }
    
    func dial(address: String, option: MediaOption, completionHandler: CompletionHandler?) {
        let dialAction: () -> Void = {
            self.prepareMediaSession(option)
            
            var localInfo = self.createLocalInfo(self.mediaSession.getLocalSdp())
            localInfo.updateValue(["address": address], forKey: "invitee")
            CallClient().join(localInfo) {
                self.onJoinCallCompleted($0, completionHandler: completionHandler)
            }
            
            self.to = address
        }
        
        doCallAction(dialAction, option: option, completionHandler: completionHandler)
    }
    
    func updateMedia(sendingAudio: Bool, _ sendingVideo: Bool){
        let mediaUrl = info?.selfMediaUrl
        assert(mediaUrl != nil, "mediaUrl is nil")
        
        let mediaInfo = info?.selfMediaInfo
        assert(mediaInfo != nil, "mediaInfo is nil")
        
        let audioMuted = !sendingAudio
        let videoMuted = !sendingVideo
        
        let localInfo = createLocalInfo((mediaInfo?.sdp)!, audioMuted: audioMuted, videoMuted: videoMuted)
        CallClient().updateMedia(mediaUrl!, localInfo: localInfo) {
            switch $0.result {
            case .Success(let value):
                self.updateCallInfo(value)
                Logger.info("Success: update media")
            case .Failure(let error):
                Logger.error("Failure: \(error.localizedFailureReason)")
            }
        }
    }
    
    func updateCallInfo(newInfo: CallInfo) {
        if self.info == nil {
            setCallInfo(newInfo)
            state.update()
            return
        }
        
        let result = CallInfoSequence.overwrite(oldValue: self.info!.sequence!, newValue: newInfo.sequence!)
        switch (result) {
        case .True:
            handleRemoteMediaChange(newInfo)
            handleEnableDTMFChange(newInfo)
            setCallInfo(newInfo)
            state.update()
        case .DeSync:
            fetchCallInfo()
        default:
            break
        }
    }
    
    func isMediaSessionAssociated(session: MediaSession) -> Bool {
        return mediaSession.isMediaSessionAssociated(session)
    }
    
    private func handleRemoteMediaChange(newInfo: CallInfo) {
        var mediaChangeType: RemoteMediaChangeType?
        
        if isRemoteVideoStateChanged(newInfo) {
            mediaChangeType = newInfo.remoteVideoMuted ?
                RemoteMediaChangeType.RemoteVideoMuted : RemoteMediaChangeType.RemoteVideoUnmuted
        }
        
        if isRemoteAudioStateChanged(newInfo) {
            mediaChangeType = newInfo.remoteAudioMuted ?
                RemoteMediaChangeType.RemoteAudioMuted : RemoteMediaChangeType.RemoteAudioUnmuted
        }
        
        guard mediaChangeType != nil else {
            return
        }
        
        setCallInfo(newInfo)
        CallNotificationCenter.sharedInstance.notifyRemoteMediaChanged(self, mediaUpdatedType: mediaChangeType!)
    }
    
    private func handleEnableDTMFChange(newInfo: CallInfo) {
        if isDTMFEnabledChanged(newInfo) {
            CallNotificationCenter.sharedInstance.notifyEnableDTMFChanged(self)
        }
    }
    
    private func isRemoteVideoStateChanged(newInfo: CallInfo) -> Bool {
        return info!.remoteVideoMuted != newInfo.remoteVideoMuted
    }
    
    private func isRemoteAudioStateChanged(newInfo: CallInfo) -> Bool {
        return info!.remoteAudioMuted != newInfo.remoteAudioMuted
    }
    
    private func isDTMFEnabledChanged(newInfo: CallInfo) -> Bool {
        return info!.enableDTMF != newInfo.enableDTMF
    }
    
    private func prepareMediaSession(option: MediaOption) {
        mediaSession.prepare(option)
    }
    
    private func fetchCallInfo() {
        CallClient().fetchCallInfo(url, completionHandler: onFetchCallInfoCompleted)
    }
    
    private func setCallInfo(info: CallInfo) {
        self.info = info
    }
    
    private func createLocalInfo(localSdp: String, audioMuted: Bool = false, videoMuted: Bool = false) -> RequestParameter {
        let mediaInfo = MediaInfo(sdp: localSdp, audioMuted: audioMuted, videoMuted: videoMuted, reachabilities: reachabilityService.feedback?.reachabilities)
        let mediaInfoJSON = Mapper().toJSONString(mediaInfo, prettyPrint: true)
        let localMedias = [["type": "SDP", "localSdp": mediaInfoJSON!]]
        
        return RequestParameter(["deviceUrl": deviceUrl!, "localMedias": localMedias])
    }
    
    private func onJoinCallCompleted(response: ServiceResponse<CallInfo>, completionHandler: CompletionHandler?) {
        switch response.result {
        case .Success(let value):
            updateCallInfo(value)
            if let remoteSdp = self.info?.remoteSdp {
                self.mediaSession.setRemoteSdp(remoteSdp)
            } else {
                Logger.error("Failure: remoteSdp is nil")
            }
            self.mediaSession.startMedia()
            CallManager.sharedInstance.addCall(self.url, call: self)
            from = info?.hostEmail
            
            Logger.info("Success: join call")
            completionHandler?(true)
            
        case .Failure(let error):
            self.mediaSession.stopMedia()
            Logger.error("Failure: \(error.localizedFailureReason)")
            completionHandler?(false)
        }
    }
    
    private func onFetchCallInfoCompleted(response: ServiceResponse<CallInfo>) {
        switch response.result {
        case .Success(let value):
            updateCallInfo(value)
            Logger.info("Success: fetch call info")
        case .Failure(let error):
            Logger.error("Failure: \(error.localizedFailureReason)")
        }
    }
    
    private func doCallAction(action: () -> Void, option: MediaOption, completionHandler: CompletionHandler?) {
        guard option.hasVideo else {
            action()
            return
        }
        
        VideoLicense.sharedInstance.checkActivation() { isActivated in
            if isActivated {
                action()
            } else {
                Logger.warn("Video license has not been activated")
                completionHandler?(false)
            }
        }
    }
}


